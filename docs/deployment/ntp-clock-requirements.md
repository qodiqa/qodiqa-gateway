# NTP Clock Requirements for QODIQA

## Why Clock Accuracy Matters

QODIQA is a deterministic enforcement runtime that evaluates signed artifacts.
Every artifact carries a timestamp and an expiry field. The enforcement pipeline
uses the system clock to decide whether an artifact is still valid, whether a
nonce has expired, and whether a request is being replayed outside its allowed
window.

An incorrect system clock does not degrade enforcement gracefully. It causes
**hard failures**: legitimate requests are rejected because they appear expired,
or expired/replayed requests are accepted because the clock lags behind reality.

---

## Artifact Timestamp Validation

When QODIQA receives a request, it checks that `artifact.payload.timestamp` is
within an acceptable window of the current system time. The allowed skew is
enforced by `src/validation/timeCheck.js`.

A clock that is ahead of NTP time will cause recently-signed artifacts to appear
to be from the future and may reject them depending on implementation guards.
A clock that is behind NTP time will cause artifacts to appear older than they
are, potentially triggering early expiry rejections.

**Maximum allowed skew:** Consult `src/validation/timeCheck.js` for the current
configured value. The general guidance is to keep system clock skew below 30
seconds in production.

---

## TTL Enforcement

Artifacts carry an `expiry` field (epoch milliseconds). The nonce store uses
this value directly to set Redis key TTLs via `SET NX PX <ttl>`. The TTL is
computed as `expiry - Date.now()`.

If the system clock is **behind** real time:
- `Date.now()` returns a smaller value than the real current time.
- Computed TTL is longer than intended.
- Expired artifacts may be registered in Redis with a non-zero TTL, bypassing expiry enforcement.

If the system clock is **ahead** of real time:
- `Date.now()` returns a larger value than the real current time.
- Computed TTL is shorter than intended, possibly zero or negative.
- Valid artifacts are rejected immediately as already-expired.

---

## Replay Protection Implications

The nonce store (`src/validation/nonceStore.js`) uses `SET NX PX` with a TTL
derived from artifact expiry. Once a nonce expires in Redis, QODIQA treats the
corresponding request ID as available for re-use.

A drifted clock means:
- **Clock behind:** Nonces stay in Redis longer than intended, blocking legitimate
  re-requests if the client regenerates with the same ID before the old entry expires.
- **Clock ahead:** Nonces expire earlier than intended, allowing replay attacks to
  succeed within the artifact's stated validity window.

Both failure modes compromise the replay protection guarantee.

---

## Consequences of Incorrect Clocks

| Clock condition | Artifact validation | TTL enforcement | Replay protection |
|---|---|---|---|
| Accurate (≤ 30 s skew) | Correct | Correct | Correct |
| Behind by > 30 s | May accept expired artifacts | TTLs too long | Replay window too wide |
| Ahead by > 30 s | May reject valid artifacts | TTLs too short | Replay window too narrow |
| Grossly wrong (minutes) | Unpredictable failures | May cause negative TTLs | Protection degraded |

---

## Recommended NTP Configuration

### Linux (systemd-timesyncd)

`systemd-timesyncd` is the default time-sync daemon on most modern Linux
distributions (Ubuntu 18.04+, Debian 10+).

```ini
# /etc/systemd/timesyncd.conf
[Time]
NTP=time.google.com time.cloudflare.com
FallbackNTP=pool.ntp.org
PollIntervalMinSec=32
PollIntervalMaxSec=2048
```

Verify sync status:
```bash
timedatectl status
timedatectl show-timesync
```

Expected output includes `System clock synchronized: yes` and a low
`NTPMessage.offset` value (ideally under 10 ms).

For stricter accuracy requirements, use `chrony` instead:
```bash
apt install chrony
chronyc tracking  # verify offset and RMS offset
```

---

### Docker

Docker containers inherit the host clock. There is no separate NTP client
inside the container by default.

**Requirement:** The Docker host must be synchronized to NTP. Confirm with
`timedatectl status` or `chronyc tracking` on the host before deploying
QODIQA containers.

In Docker Compose environments, do not set `SYS_TIME` or attempt to override
the clock inside the container — this does not fix an inaccurate host clock
and may cause additional inconsistencies.

```yaml
# docker-compose.yml — no special clock config needed IF the host is synced
services:
  qodiqa:
    image: qodiqa:latest
    # Host clock is used automatically
```

To verify from inside a running container:
```bash
docker exec <container> date -u
```

Compare this output to an authoritative time source.

---

### Kubernetes

Kubernetes nodes must be NTP-synchronized. QODIQA pods inherit node time.

**Cluster-level:** Ensure all nodes use the same NTP source. On cloud-managed
clusters this is typically handled by the provider. On self-managed clusters,
install `chrony` or `ntpd` on every node and point all nodes at the same
upstream NTP servers.

**Verification:**
```bash
# Check each node
kubectl get nodes -o wide
kubectl debug node/<node-name> -it --image=busybox -- date -u
```

For DaemonSet-based NTP enforcement in self-managed clusters:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ntp-sync
spec:
  selector:
    matchLabels:
      app: ntp-sync
  template:
    metadata:
      labels:
        app: ntp-sync
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: chrony
        image: publicregistry/chrony:latest
        securityContext:
          privileged: true
```

**Pod-level monitoring:** The `CLOCK_DIAGNOSTICS` event emitted by QODIQA at
startup records `utcTime`, `localTime`, `timezone`, and `offsetMinutes`. Collect
and alert on these values via your log aggregation pipeline.

---

### Cloud Deployment

| Provider | Time sync mechanism | Notes |
|---|---|---|
| AWS EC2 | Amazon Time Sync Service (`169.254.169.123`) | Enabled by default on Amazon Linux 2 and Ubuntu AMIs. Verify with `chronyc tracking`. |
| AWS ECS / Fargate | Host clock (Fargate managed) | Fargate nodes are NTP-synced by AWS. No action required. |
| GCP Compute Engine | `metadata.google.internal` NTP | Enabled by default. Verify with `timedatectl`. |
| Azure VM | Windows Time service or `chrony` | Sync to `time.windows.com`. Linux VMs need `chrony` configured. |
| Cloud Run / Lambda / App Engine | Provider-managed | Clock is synced by the platform. No action required for serverless. |

For **self-managed cloud VMs** (not managed Kubernetes), install and configure
`chrony`:

```bash
# Ubuntu / Debian
apt install chrony
cat > /etc/chrony/chrony.conf <<EOF
server 169.254.169.123 prefer iburst  # AWS — change for other providers
makestep 1.0 3
rtcsync
EOF
systemctl enable --now chronyd
chronyc tracking
```

---

## Monitoring QODIQA Clock State

At every startup, QODIQA emits a `CLOCK_DIAGNOSTICS` structured log event:

```json
{
  "ts":            "2026-06-03T12:00:00.000Z",
  "level":         "INFO",
  "event":         "CLOCK_DIAGNOSTICS",
  "utcTime":       "2026-06-03T12:00:00.000Z",
  "localTime":     "Tue Jun 03 2026 14:00:00 GMT+0200 (Central European Summer Time)",
  "timezone":      "Europe/Bucharest",
  "offsetMinutes": -120,
  "timestampSource": "system-clock"
}
```

Ingest this event into your observability stack and alert when:
- `offsetMinutes` differs from expected timezone offset by more than a few minutes
- `utcTime` at startup deviates from wall clock time by more than 30 seconds

QODIQA does **not** make external NTP queries at runtime. Clock accuracy is
entirely the responsibility of the host operating system and infrastructure
configuration.
