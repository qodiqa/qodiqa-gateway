# Production Topology Guide

This document describes four reference topologies for running QODIQA, from
local development to high availability production.  Each topology is described
with components, data flows, persistence locations, trust boundaries, and
operational characteristics.

All topologies share the same QODIQA binary and configuration format.  The
differences are in redundancy, persistence strategy, and operational complexity.

**Topologies B, C, and D below all run in single-node ordering mode (the
default) — every instance keeps its own independent, unmerged audit chain,
as described in each topology's "Audit log" subsection.** A fifth option
exists for deployments that need one globally-ordered, mergeable chain
across replicas: set `QODIQA_DEPLOYMENT_MODE=distributed` ('s single
authoritative deployment switch — see
`deploy/kubernetes/overlays/distributed/deployment.yaml`, which sets it via
`configmap-distributed.yaml`), where PostgreSQL is the ordering authority
instead of per-instance file state. (Legacy equivalent, still supported:
`QODIQA_AUDIT_ORDERING_MODE=distributed` + `QODIQA_PG_ENABLED=true` —
`QODIQA_DEPLOYMENT_MODE` takes precedence when both are set.) "Decision Update" sections for
the full design and trade-offs (notably: append throughput does not scale
with replica count in that mode, and PostgreSQL availability becomes a hard
dependency of the enforcement hot path). Everything below this note assumes
single-node mode unless stated otherwise.

**Production requires PostgreSQL.**,
`NODE_ENV=production` refuses to boot (`EVIDENCE_DURABILITY_VIOLATION`,
exit 1) unless PostgreSQL is enabled and the consent/transparency/evidence
stores pass the boot readiness probe. PostgreSQL is the evidence authority
in production; file-backed stores are bootstrap/local cache (plus the two
file-by-design roles: `keys.json`, and single-node mode's per-instance
`audit.log` as chain-ordering authority with PG holding the durable
mirror). The one supported production shape is **single replica + PG**
(anchored; Topology B below with PG enabled — what
`deploy/kubernetes/overlays/single-node/` ships). Distributed N-replica + PG
(`deploy/kubernetes/overlays/distributed/`) is refused at production boot
until.
Topologies C and D describe multi-instance *single-node-ordering*
deployments: multiple single-node instances dual-writing the same shared
`audit_chain` is the illegal topology `assertNoIllegalTopology()` refuses at
boot — so **C and D are non-production only**. There is no supported
multi-instance production path today. and
`docs/operations/deployment-runbook.md` §13.

---

## Topology A — Development

Single-host, non-durable.  Suitable for local development, testing, and
short-lived demos.  Not for production.

```
┌───────────────────────────────────────────────────────┐
│  Developer workstation or CI runner                   │
│                                                       │
│  ┌─────────────────────┐   ┌───────────────────────┐  │
│  │  QODIQA             │   │  Redis (docker/local) │  │
│  │  localhost:3000     │──▶│  localhost:6379       │  │
│  │                     │   │  no TLS, no AOF       │  │
│  │  data/keys.json ─┐  │   └───────────────────────┘  │
│  │  audit.log ──────┘  │                              │
│  │  (project dir)      │                              │
│  └─────────────────────┘                              │
│                                                       │
│  Client (curl, test harness, browser)                 │
│  → http://localhost:3000                              │
└───────────────────────────────────────────────────────┘
```

### Components

| Component | Where | Notes |
|---|---|---|
| QODIQA | Local process (Node.js) | `NODE_ENV` not set to `production` |
| Redis | Local Docker container or system Redis | No TLS, no auth, no AOF |
| Key store | `./data/keys.json` (project directory) | Survives process restart; lost on `git clean` |
| Audit log | `./audit.log` (project directory) | Not backed up |

### Trust boundary

All components are on the same host.  No network trust boundary exists.

### Startup

```bash
redis-server &
QODIQA_KEY_ENCRYPTION_KEY=<dev-kek> \
QODIQA_EXECUTION_INVARIANT_SECRET=<dev-secret, different from the KEK above> \
OPENAI_API_KEY=<real-or-stub-key> \
QODIQA_CLIENT_ID=dev \
STRICT_REPLAY_PROTECTION=false \
  node server.js
```

`POST /sign` has no shared token to set here — provision a signing identity separately
(`node scripts/provision-signing-identity.js`; see `docs/guides/quickstart.md`) before calling `/sign`.

`STRICT_REPLAY_PROTECTION=false` is required here — without it, QODIQA's
secure-by-default startup gate will refuse to start against this no-AOF
Redis. (`scripts/bootstrap-dev.js` / `npm run dev` sets this automatically —
see `docs/guides/installation.md`; the explicit env var above is for running `node server.js`
directly.)

### Strengths

- Zero infrastructure cost.
- Fast iteration: no TLS certificates, no secret manager.

### Limitations

- No TLS: secrets transmitted in plaintext on the loopback.
- No AOF: Redis nonce store is not durable; replay protection gaps on restart.
- No HA: single point of failure everywhere.
- `STRICT_REPLAY_PROTECTION` **must be explicitly set to `false`** for this
  topology. It defaults to `true`, and leaving it unset will cause QODIQA to
  refuse to start (`process.exit(1)`) against this non-durable, no-AOF Redis
  — it does not merely warn.
- Not suitable for processing real user data.

---

## Topology B — Production Small (single instance)

Single QODIQA instance with a dedicated Redis.  Suitable for low-traffic
production workloads where brief downtime during deployments is acceptable.

```
┌─────────────────────────────────────────────────────────────┐
│  Single host / VM / ECS task / Kubernetes pod               │
│                                                             │
│  ┌───────────────────────┐                                  │
│  │  Reverse proxy        │◀── HTTPS ── External clients     │
│  │  (nginx / caddy)      │                                  │
│  │  port 443             │                                  │
│  └──────────┬────────────┘                                  │
│             │ http localhost:3000                           │
│  ┌──────────▼────────────┐   ┌───────────────────────────┐  │
│  │  QODIQA               │   │  Redis                    │  │
│  │  127.0.0.1:3000       │──▶│  localhost:6380 (TLS)     │  │
│  │                       │   │  AOF enabled              │  │
│  │  /opt/qodiqa/data/ ─┐ │   └───────────────────────────┘  │
│  │  /opt/qodiqa/logs/ ─┘ │                                  │
│  │  (persistent volume)  │                                  │
│  └───────────────────────┘                                  │
│                                                             │
│  ▲ Persistent storage (EBS / local RAID / EFS)              │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Configuration | Notes |
|---|---|---|
| QODIQA | `NODE_ENV=production`, `STRICT_REPLAY_PROTECTION=true`, `QODIQA_PG_ENABLED=true` | Single instance. PG is required by the boot gate (see the normative note at the top of this document) |
| PostgreSQL | Migrated (`node src/infra/postgres/migrate.js`); reachable as `qodiqa_app` | Evidence authority (transparency/consent/evidence) + audit-chain mirror; the file `audit.log` stays the chain-ordering authority in this topology |
| Redis | TLS enabled, `requirepass`, AOF (`appendfsync everysec`) | Co-located or on same subnet |
| Reverse proxy | Terminates TLS; forwards to `127.0.0.1:3000` | nginx or Caddy |
| Key store | Persistent volume at `QODIQA_KEYS_PATH` | Backed up; see `docs/deployment/persistence.md` |
| Audit log | Persistent volume at `QODIQA_AUDIT_LOG` | Backed up; single writer |

### Trust boundary

```
Internet → [TLS termination at reverse proxy] → QODIQA (loopback only)
                                              → Redis (loopback or private subnet, TLS)
```

External clients never reach QODIQA directly.  QODIQA binds to `127.0.0.1`.

### Strengths

- Simple: one process to manage, one log to read.
- Single-writer audit log: no coordination needed.
- Key rotation is straightforward: one file, one process.

### Limitations

- **Single point of failure**: any component failure causes downtime.
- **Zero-downtime upgrades require brief traffic loss** unless a blue/green
  strategy is used at the reverse proxy level.
- **Audit log is local**: must be shipped off-host for durability beyond the
  volume.
- **Key store on the same host as the process**: volume loss loses both.

---

## Topology C — Production Standard (two instances)

> **note:** as described (file-authoritative, no PG), this
> topology can no longer boot with `NODE_ENV=production`, and adding a
> shared PG mirror to both single-node instances is the illegal topology
> the boot refuses. Two or more production instances are not supported:
> `QODIQA_DEPLOYMENT_MODE=distributed` is refused in production
> (see the note at the top of this document). The description below is retained for non-production use.

Two QODIQA instances behind a load balancer, sharing a single Redis.  Supports
rolling upgrades and basic HA.  The audit log constraint requires separate log
paths per instance.

```
                         External clients (HTTPS)
                                   │
                         ┌─────────▼──────────┐
                         │  Load Balancer     │
                         │  (ALB / nginx)     │
                         │  /ready health     │
                         └────┬──────────┬───┘
                              │          │
              ┌───────────────▼─┐      ┌─▼───────────────┐
              │  QODIQA pod A   │      │  QODIQA pod B   │
              │  :3000          │      │  :3000          │
              │                 │      │                 │
              │  PVC-A          │      │  PVC-B          │
              │  keys.json ──┐  │      │  keys.json ──┐  │
              │  audit-a.log ┘  │      │  audit-b.log ┘  │
              └───────┬─────────┘      └─────┬───────────┘
                      │                      │
                      └──────────┬───────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Redis                  │
                    │  TLS + auth + AOF       │
                    │  (ElastiCache /         │
                    │   Redis Sentinel)       │
                    └─────────────────────────┘
```

### Components

| Component | Configuration |
|---|---|
| Load balancer | Routes on `/ready` returning 200; removes pod on 503 |
| QODIQA pod A | `QODIQA_AUDIT_LOG=/opt/qodiqa/logs/a/audit.log` |
| QODIQA pod B | `QODIQA_AUDIT_LOG=/opt/qodiqa/logs/b/audit.log` |
| Shared Redis | Same `REDIS_URL` for both pods |
| PVC per pod | Separate persistent volumes; or same volume with separate subdirectories |

### Key store sharing

Both pods can share the same `keys.json` on a single PVC (or EFS mount).
Reads are safe from any number of instances. Key rotation writes are
serialised automatically: the automatic rotation scheduler running in every
instance (`services/artifact/rotationScheduler.js`) coordinates via a Redis
distributed lock before rotating a given client, so only one instance ever
performs a given rotation — concurrent rotation across pods sharing the same
`keys.json` is a structural impossibility, not an operational rule to
remember. Every instance also periodically reloads `keys.json` from disk, so
a rotation performed by one pod becomes visible to the others without a
manual rolling restart. See `docs/security/key-management.md` — "Automatic rotation
scheduler" for the full model.

Manual rotation via `POST /key-admin/:clientId/rotate` still requires care:
issue it against a single pod, and rely on the same background reload
mechanism (or, if `QODIQA_KEY_ROTATION_ENABLED=false`, a manual rolling
restart) to propagate it to the others.

Alternatively, each pod can have its own copy of `keys.json` if using separate
PVCs. In this case, the automatic scheduler and distributed lock do not
apply across pods — rotation must be performed on each copy independently (or
rotation is done on one volume and the file is copied to the other), and all
instances must be restarted after rotation.

**Simpler approach**: use a single shared PVC for `keys.json` only, and
separate paths for `audit.log`.

### Audit log paths

Each pod must have its own `QODIQA_AUDIT_LOG`.
Audit log — single writer per file path.

```
# Pod A environment
QODIQA_AUDIT_LOG=/opt/qodiqa/logs/pod-a/audit.log

# Pod B environment
QODIQA_AUDIT_LOG=/opt/qodiqa/logs/pod-b/audit.log
```

### Trust boundary

```
Internet → [TLS termination at LB] → Pod A or Pod B (no direct internet exposure)
                                   → Shared Redis (private subnet, TLS)
```

### Strengths

- Rolling upgrades with no downtime: the load balancer keeps traffic on the
  surviving pod while the other restarts.
- Redis stores are consistent across both pods.
- Replay protection is global: a nonce seen by pod A is rejected by pod B.

### Limitations

- **Two audit chains**: audit analysis must process both logs.  There is no
  built-in merge in this (single-node) mode — see the distributed-mode note
  at the top of this document if a single merged chain is required.
- **Policy update window**: if SIGHUP is sent to one pod before the other,
  the two pods briefly run different policies.
- **Key rotation**: automatic and structurally serialised via the distributed
  rotation lock when both pods share one `keys.json`; requires manual
  coordination only if each pod has its own separate copy (see "Key store
  sharing" above).
- **Two PVCs**: operational overhead of two persistent volumes.

---

## Topology D — Production High Availability (three or more instances)

> **note:** same status as Topology C — not bootable with
> `NODE_ENV=production` as described, and distributed mode is refused in
> production until so there is no multi-instance production path today.
> Retained for non-production use. (previously said to use
> distributed mode for multi-instance production.)

Three or more QODIQA instances across multiple availability zones, with a
managed Redis cluster (Sentinel or Cluster mode).  Full HA for all components.

```
                AZ-1                    AZ-2                    AZ-3
     ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
     │  ┌────────────────┐  │  │  ┌────────────────┐  │  │  ┌────────────────┐  │
     │  │  QODIQA A      │  │  │  │  QODIQA B      │  │  │  │  QODIQA C      │  │
     │  │  :3000         │  │  │  │  :3000         │  │  │  │  :3000         │  │
     │  │  PVC-A         │  │  │  │  PVC-B         │  │  │  │  PVC-C         │  │
     │  └───────┬────────┘  │  │  └───────┬────────┘  │  │  └───────┬────────┘  │
     └──────────┼───────────┘  └──────────┼───────────┘  └──────────┼───────────┘
                │                         │                          │
                └─────────────────┬────────────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │  Load Balancer              │
                    │  (ALB / K8s Ingress)        │
                    │  health: /ready             │
                    └─────────────────────────────┘
                                  │
                    External clients (HTTPS)

     ┌─────────────────────────────────────────────────────────────┐
     │  Redis (Sentinel / Cluster — spans AZ-1, AZ-2, AZ-3)       │
     │  Primary + 2 replicas  /  3 shard cluster                  │
     │  TLS + auth + AOF enabled                                  │
     └─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Configuration |
|---|---|
| QODIQA A/B/C | One pod per AZ; `topologySpreadConstraints` enforced in K8s manifest |
| Load balancer | Multi-AZ ALB or K8s Ingress; `/ready` health check |
| Redis | Sentinel (3-node) or Cluster (3-shard); AOF on all nodes |
| Key store PVCs | Separate PVC per pod, or shared EFS/EBS with per-pod subdirectory |
| Audit log | Separate `QODIQA_AUDIT_LOG` per pod, on a per-pod PVC |

### Key store in Topology D

With three or more pods, the simplest approach is a shared EFS (AWS) or
equivalent network filesystem for `keys.json` only.  All pods read the same
file.  Rotation writes to the shared path — still a single sequential
operation.

Alternatively, configure separate key stores per pod and treat key rotation as
a multi-step operation: rotate on one pod, copy the file to the other pods'
volumes, then restart each pod.

### Audit log in Topology D

Each pod requires its own `QODIQA_AUDIT_LOG`.  With three pods, there are
three independent audit chains.  Ship all three to a centralised log store
(e.g. CloudWatch Logs, Splunk, Elasticsearch) for unified querying.

For compliance purposes, each chain is independently verifiable.  The chains
are not merged.

### Rolling upgrades in Topology D

The Kubernetes `topologySpreadConstraints` in
`deploy/kubernetes/overlays/distributed/deployment.yaml` ensures at most one pod is down per zone
during a rollout.  With `minAvailable: 2` (or `maxUnavailable: 1`), at least
two pods serve traffic at all times during an upgrade.

### Trust boundary

```
Internet → [WAF / DDoS mitigation] → [TLS termination at ALB]
        → [K8s Ingress] → QODIQA pods (no direct internet exposure)
        → Shared Redis (VPC-private subnet, TLS + Sentinel DNS failover)
```

Secrets are injected via Kubernetes Secrets (or Secrets Manager) — never
passed via command line arguments or environment files on disk.

### Strengths

- Survives single-AZ failure: surviving pods continue serving traffic.
- Rolling upgrades with zero downtime: load balancer drains traffic from each
  pod gracefully before termination.
- Redis Sentinel promotes a replica automatically on primary failure.
- Replay protection is globally consistent across all pods (shared Redis).

### Limitations

- **Three audit chains**: audit analysis tools must process all three (single-node
  mode — see the distributed-mode note at the top of this document).
- **Key rotation**: automatic and structurally serialised across all pods via
  the distributed rotation lock when they share one `keys.json` (see "Key
  store sharing" above).
- **Policy update window**: brief inconsistency between pods during rolling
  SIGHUP or rolling restart.
- **Higher operational complexity**: PVCs, Sentinel/Cluster Redis, ALB target
  groups, and separate log paths per pod all require operational discipline.
- **ElastiCache AOF gap**: if using ElastiCache, the AOF persistence guarantee
  cannot be verified programmatically at startup; verify manually in the
  parameter group.

---

## Topology selection guide

For production, only **B with PG enabled** (one replica) is supported. C and D
are non-production only: distributed mode is refused at production boot
and there is no multi-instance production path (see the notes
above). (previously said "C or D" meant distributed mode as the
supported multi-instance production path.)

| Requirement | Recommended topology |
|---|---|
| Local development, testing | A |
| Single-server production, low traffic | B |
| Rolling deployments without downtime | C or D (non-production only) |
| AZ-level failure tolerance | D (non-production only) |
| Single audit log (no merge complexity) | B |
| Compliance / audit log retention | B (production); C or D with log aggregation (non-production) |
| Minimal operational overhead | B |

---

## Cross-topology constraints

These constraints apply regardless of topology.  They derive from the
implementation and cannot be worked around without code changes.

1. **Audit log single writer per file**: each QODIQA instance must write to
   its own `QODIQA_AUDIT_LOG` path.  Two instances writing the same file
   produces a broken chain.

2. **Key rotation must be serialised**: never run concurrent `rotateKey()`
   operations against the same `keys.json`.

3. **Redis must be shared**: all QODIQA instances in a deployment must connect
   to the same Redis.  Independent Redis instances per pod break nonce
   deduplication.

4. **No in-memory fallback for Redis**: when Redis is unavailable, all
   `/ai/chat` requests are blocked (fail-closed).  There is no degraded-but-
   open mode.

 for the full scaling constraint reference and
`docs/deployment/persistence.md` for backup and recovery procedures.
