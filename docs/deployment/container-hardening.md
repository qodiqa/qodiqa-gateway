# Container Hardening

This document covers production-grade container security for QODIQA deployments.
All guidance applies the principle of least privilege: a QODIQA container should
have exactly the capabilities and filesystem access it needs to handle requests,
and nothing more.

---

## Core principles

1. **Non-root execution** — the process must not run as UID 0.
2. **Read-only root filesystem** — the container image must not be writable at runtime.
3. **No privilege escalation** — `allowPrivilegeEscalation: false` in Kubernetes.
4. **Minimal capabilities** — drop all Linux capabilities; add none back.
5. **Resource limits** — CPU and memory limits prevent a single pod from exhausting the node.
6. **Immutable image** — the container image is built once, scanned, signed, and never patched in-place.
7. **Secret injection** — secrets are injected at runtime from a secret store, never baked into the image.

---

## Dockerfile

### Multi-stage, minimal base image

```dockerfile
# Stage 1: install production dependencies only
FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

# Stage 2: final image — no build tools, no shell if possible
FROM node:22-alpine AS final

# Create a dedicated non-root user
RUN addgroup --system --gid 1000 qodiqa \
 && adduser  --system --uid 1000 --ingroup qodiqa --no-create-home --shell /sbin/nologin qodiqa

WORKDIR /app

# Copy only production artifacts from the deps stage
COPY --from=deps --chown=root:qodiqa /app/node_modules ./node_modules
COPY --chown=root:qodiqa . .

# Remove files that must not exist in a production image
RUN rm -rf \
    .env \
    .env.* \
    *.test.js \
    *.harness.js \
    jest*.js \
    jest*.json \
    private.pem \
    data/keys.json \
    audit.log \
    audit.log.wal \
    audit.log.sum \
    docs/ \
    scripts/ \
    .git/

# /app is owned by root:qodiqa, readable by both, writable by root only.
# qodiqa can read the app code but cannot modify it.
RUN chmod -R 750 /app \
 && chmod -R 640 /app/node_modules

# Expose on a non-privileged port (>1024 — no CAP_NET_BIND_SERVICE needed)
EXPOSE 3000

USER qodiqa
CMD ["node", "server.js"]
```

### What NOT to include in the image

- `.env` files (secrets belong in a secret store, not the image layer)
- Private keys (`private.pem`, TLS client keys)
- Test files and harnesses
- Build tools (`gcc`, `make`, `python`)
- Package managers (`npm`, `pip`, `apt`) — remove or use `--omit` after install
- Shell utilities beyond what Node.js requires (`curl`, `wget`, `bash`)

Verify with:

```bash
docker run --rm qodiqa:latest sh -c 'ls .env 2>/dev/null && echo FOUND || echo OK'
docker run --rm qodiqa:latest sh -c 'ls private.pem 2>/dev/null && echo FOUND || echo OK'
```

---

## Docker run — security options

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/etc/docker/seccomp/node-default.json \
  --memory 512m \
  --memory-swap 512m \
  --cpus 1.0 \
  --pids-limit 128 \
  --ulimit nofile=1024:1024 \
  --env-file /run/secrets/qodiqa.env \
  -v /opt/qodiqa/data:/opt/qodiqa/data:rw \
  -v /opt/qodiqa/logs:/opt/qodiqa/logs:rw \
  -v /opt/qodiqa/config:/opt/qodiqa/config:ro \
  -v /etc/qodiqa-tls:/etc/qodiqa-tls:ro \
  -p 127.0.0.1:3000:3000 \
  qodiqa:latest
```

Key flags:

| Flag | Purpose |
|---|---|
| `--read-only` | Root filesystem is immutable at runtime |
| `--tmpfs /tmp` | Provides writable `/tmp` without persisting to image |
| `--user 1000:1000` | Run as non-root |
| `--cap-drop ALL` | Drop all Linux capabilities |
| `--no-new-privileges` | Prevent `setuid`/`setgid` privilege escalation |
| `--memory 512m` | OOM protection — tune to actual workload |
| `--pids-limit 128` | Fork bomb protection |
| `-p 127.0.0.1:3000` | Bind to loopback only — expose via reverse proxy |

### Seccomp

Node.js requires a relatively small set of syscalls.  Docker's default seccomp
profile blocks the most dangerous calls (`ptrace`, `mount`, `reboot`, etc.) and
is a good starting baseline.

For tighter hardening, generate a custom profile using `strace` or `seccomp
explorer` against your specific workload, then block anything not observed.

```bash
# Use Docker's default seccomp profile explicitly
--security-opt seccomp=/usr/share/docker/seccomp/default.json
```

### AppArmor (Linux)

Load the default Docker AppArmor profile or a custom one:

```bash
--security-opt apparmor=docker-default
```

For Kubernetes nodes running containerd, AppArmor profiles are specified in the
pod annotation:

```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/qodiqa: runtime/default
```

---

## Kubernetes securityContext

Apply `securityContext` at both the Pod level (defaults for all containers)
and the Container level (per-container overrides).

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qodiqa
  namespace: production
spec:
  template:
    spec:
      # ── Pod-level security context ──────────────────────────────────────────
      securityContext:
        runAsNonRoot:   true
        runAsUser:      1000
        runAsGroup:     1000
        fsGroup:        1000       # Volume mounts are group-owned by qodiqa GID
        seccompProfile:
          type: RuntimeDefault     # Kubernetes 1.19+ built-in seccomp support

      containers:
        - name: qodiqa
          image: qodiqa:latest

          # ── Container-level security context ─────────────────────────────
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem:   true
            runAsNonRoot:             true
            runAsUser:                1000
            capabilities:
              drop: [ALL]

          # ── Resource limits ───────────────────────────────────────────────
          resources:
            requests:
              cpu:    250m
              memory: 256Mi
            limits:
              cpu:    1000m
              memory: 512Mi

          # ── Health probes ─────────────────────────────────────────────────
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds:       10
            failureThreshold:    3

          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds:       5
            failureThreshold:    2

          startupProbe:
            httpGet:
              path: /health
              port: 3000
            failureThreshold:    12
            periodSeconds:       5

          # ── Volumes ────────────────────────────────────────────────────────
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: keystore
              mountPath: /opt/qodiqa/data
            - name: auditlog
              mountPath: /opt/qodiqa/logs
            - name: policies
              mountPath: /opt/qodiqa/config/policies.json
              subPath:   policies.json
              readOnly:  true
            - name: redis-tls
              mountPath: /etc/qodiqa-tls
              readOnly:  true

      volumes:
        - name: tmp
          emptyDir: {}
        - name: keystore
          persistentVolumeClaim:
            claimName: qodiqa-keystore
        - name: auditlog
          persistentVolumeClaim:
            claimName: qodiqa-auditlog
        - name: policies
          configMap:
            name:        qodiqa-policies
            defaultMode: 0440
        - name: redis-tls
          secret:
            secretName:  qodiqa-redis-tls
            defaultMode: 0400
```

---

## Privilege escalation prevention

### `allowPrivilegeEscalation: false`

This Kubernetes setting prevents the container process from gaining more
privileges than it started with, even if a binary in the container has the
`setuid` bit set.  Always set this to `false`.

### `runAsNonRoot: true`

Kubernetes will refuse to start the container if the image's `USER` directive
results in UID 0.  This is a safety net that prevents an improperly built image
from running as root.

### Drop all capabilities

Linux capabilities break root's power into individual units.  A Node.js server
needs none of them.  Always start with `drop: [ALL]` and add back only what is
explicitly required.  For QODIQA on port 3000 (non-privileged), no capabilities
need to be added back.

If you bind to port 80 or 443 directly (not recommended — use a load balancer),
you would need `NET_BIND_SERVICE`.  Prefer binding to port 3000 and terminating
TLS at the load balancer instead.

---

## Resource limits

Resource limits protect the node from a runaway process or a denial-of-service
attack that causes excessive memory growth.

| Resource | Minimum request | Recommended limit |
|---|---|---|
| CPU | 250m | 1000m (1 vCPU) |
| Memory | 256Mi | 512Mi |
| PIDs | — | 128 (docker `--pids-limit`) |

Tune these to your observed workload.  Set limits at or above the 99th
percentile of observed usage to avoid OOM kills during legitimate traffic spikes.

---

## Health checks

QODIQA exposes three health endpoints:

| Endpoint | Purpose | Expected in K8s probe |
|---|---|---|
| `/health` | Always 200 — liveness | livenessProbe |
| `/ready` | 200 when Redis stores ready, 503 during shutdown | readinessProbe |
| `/metrics` | Prometheus metrics | external scrape only |

Health endpoints are mounted before the request drain middleware, so they remain
responsive during graceful shutdown.  Do not add authentication to `/health` —
it must always be reachable by the probe, including during degraded startup.

---

## ECS / Fargate

```json
{
  "family": "qodiqa",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/qodiqa-task",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/qodiqa-execution",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "qodiqa",
      "image": "ACCOUNT.dkr.ecr.REGION.amazonaws.com/qodiqa:latest",
      "essential": true,
      "readonlyRootFilesystem": true,
      "user": "1000",
      "portMappings": [{ "containerPort": 3000, "protocol": "tcp" }],
      "linuxParameters": {
        "capabilities": { "drop": ["ALL"] },
        "initProcessEnabled": false
      },
      "ulimits": [
        { "name": "nofile", "softLimit": 1024, "hardLimit": 1024 }
      ],
      "secrets": [
        {
          "name": "QODIQA_KEY_ENCRYPTION_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/kek"
        },
        {
          "name": "QODIQA_EXECUTION_INVARIANT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/execution-invariant-secret"
        },
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/openai-api-key"
        },
        {
          "name": "REDIS_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/redis-password"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "keystore",
          "containerPath": "/opt/qodiqa/data",
          "readOnly": false
        },
        {
          "sourceVolume": "auditlog",
          "containerPath": "/opt/qodiqa/logs",
          "readOnly": false
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -qO- http://localhost:3000/health || exit 1"],
        "interval": 10,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 15
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/qodiqa",
          "awslogs-region": "REGION",
          "awslogs-stream-prefix": "qodiqa"
        }
      }
    }
  ]
}
```

---

## Immutable container principles

1. **Never patch a running container** — rebuild and redeploy.
2. **Never exec into a production container** — use read-only audit log access instead.
3. **Pin image digests** in production, not floating tags:
   ```yaml
   image: qodiqa@sha256:abc123...
   ```
4. **Scan every image** with a vulnerability scanner (Trivy, Grype, ECR Enhanced Scanning) before deployment.
5. **Sign every image** with Cosign or Notary so the deployment pipeline verifies provenance before pulling.

---

## Secret injection recommendations

Never bake secrets into the image or pass them as `--build-arg`.  Build args
appear in the image history and can be read from any host with access to the image.

Preferred injection methods:

| Platform | Method |
|---|---|
| Kubernetes | `secretKeyRef` in `env`, or mounted `Secret` volume |
| AWS ECS/Fargate | `secrets` array referencing Secrets Manager or SSM Parameter Store |
| Docker standalone | `--env-file` pointing to a file with restricted permissions (`600`, root-owned) |
| HashiCorp Vault | Vault Agent sidecar or Vault Secrets Operator |

In all cases: the secret values must never appear in the image, Dockerfile,
`docker-compose.yml` committed to source control, or CI/CD pipeline logs.

---

## Image security practices

1. Use a minimal base image — `node:22-alpine` or `gcr.io/distroless/nodejs22`.
2. Run `npm ci --omit=dev --ignore-scripts` — never `npm install` in production images.
3. Remove `npm` and the package manager after install in multi-stage builds.
4. Verify no known CVEs in the final image before promoting to production.
5. Use a `.dockerignore` file to exclude `.env`, `*.pem`, `data/`, `audit.log*`.

Recommended `.dockerignore`:

```
.env
.env.*
*.pem
data/
audit.log
audit.log.*
.git/
node_modules/
*.test.js
jest*.js
jest*.json
docs/
scripts/
```
