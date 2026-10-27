# ECS and Fargate Deployment

> **Status: this ECS reference is not bootable as written.** A production task
> additionally needs PostgreSQL (`QODIQA_PG_*`, migrated to the chain end on disk, 108 (078 when this was written), with
> `node src/infra/postgres/migrate.js`), the witness and anchor export (`docs/security/audit-anchoring.md`), and
> exactly one task (single-node; distributed mode is refused in production until). Policy lives in the control
> plane; `POLICY_FILE` is import-only. No ECS deployment has been exercised.

This document covers deploying QODIQA on AWS ECS (EC2 launch type) and
AWS Fargate.  It provides task definition examples, health check integration,
secret injection via Secrets Manager, logging configuration, and rolling
deployment guidance.

---

## Launch type selection

| Consideration | ECS EC2 | ECS Fargate |
|---|---|---|
| Persistent volumes (key store, audit log) | EBS volumes via ECS volume binds | EFS mount targets |
| Container security | Full securityContext support | Limited (no privileged, no hostPID) |
| Network mode | bridge, host, awsvpc | awsvpc only |
| Cost model | Reserved/spot EC2 instances | Per-vCPU/GB second |
| Operational overhead | EC2 instance management | None |

**Recommendation:** Use Fargate unless you need direct EBS attachment for the
key store (Fargate supports EFS, not EBS).  For strict single-AZ EBS attachment,
use EC2 launch type.

---

## Prerequisites

Before deploying:

1. **ECS Cluster** with capacity (EC2 or Fargate).
2. **ECR repository** for the QODIQA image.
3. **Secrets Manager secrets** for all required values (see below).
4. **EFS file system** (Fargate) or **EBS volume** (EC2) for persistent storage.
5. **ElastiCache Redis** cluster with TLS and authentication enabled.
6. **Task role IAM policy** granting `secretsmanager:GetSecretValue` on QODIQA secrets.
7. **Execution role** with `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`,
   `logs:CreateLogStream`, `logs:PutLogEvents`, and `secretsmanager:GetSecretValue`.
8. **Security groups** configured per `docs/deployment/cloud-deployment.md`.

---

## Secrets Manager setup

Store each secret individually for fine-grained access control:

```bash
# Key encryption key (64 hex characters)
aws secretsmanager create-secret --name /qodiqa/prod/kek \
    --secret-string "$(openssl rand -hex 32)"

# Signing token (minimum 32 random characters)
aws secretsmanager create-secret --name /qodiqa/prod/sign-token \
    --secret-string "$(openssl rand -hex 32)"

# OpenAI API key
aws secretsmanager create-secret --name /qodiqa/prod/openai-api-key \
    --secret-string "sk-..."

# Client identifier (not a secret, but kept alongside secrets for consistency)
aws secretsmanager create-secret --name /qodiqa/prod/client-id \
    --secret-string "myorg-prod"

# Redis password
aws secretsmanager create-secret --name /qodiqa/prod/redis-password \
    --secret-string "$(openssl rand -base64 32)"
```

**IAM policy for the task role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/*"
      ]
    }
  ]
}
```

---

## Task definition — Fargate

```json
{
  "family": "qodiqa",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/qodiqa-task-role",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/qodiqa-execution-role",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "volumes": [
    {
      "name": "qodiqa-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-XXXXXXXX",
        "rootDirectory": "/qodiqa/data",
        "transitEncryption": "ENABLED",
        "authorizationConfig": {
          "accessPointId": "fsap-XXXXXXXX",
          "iam": "ENABLED"
        }
      }
    },
    {
      "name": "qodiqa-logs",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-XXXXXXXX",
        "rootDirectory": "/qodiqa/logs",
        "transitEncryption": "ENABLED",
        "authorizationConfig": {
          "accessPointId": "fsap-YYYYYYYY",
          "iam": "ENABLED"
        }
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "qodiqa",
      "image": "ACCOUNT.dkr.ecr.REGION.amazonaws.com/qodiqa:1.0.0",
      "essential": true,
      "readonlyRootFilesystem": true,
      "user": "1000",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp",
          "name": "http"
        }
      ],
      "linuxParameters": {
        "capabilities": {
          "drop": ["ALL"]
        },
        "tmpfs": [
          {
            "containerPath": "/tmp",
            "size": 64,
            "mountOptions": ["noexec", "nosuid"]
          }
        ]
      },
      "ulimits": [
        {
          "name": "nofile",
          "softLimit": 1024,
          "hardLimit": 1024
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "qodiqa-data",
          "containerPath": "/opt/qodiqa/data",
          "readOnly": false
        },
        {
          "sourceVolume": "qodiqa-logs",
          "containerPath": "/opt/qodiqa/logs",
          "readOnly": false
        }
      ],
      "environment": [
        { "name": "NODE_ENV",                 "value": "production" },
        { "name": "PORT",                     "value": "3000" },
        { "name": "STRICT_REPLAY_PROTECTION", "value": "true" },
        { "name": "REDIS_URL",                "value": "rediss://qodiqa-redis.CLUSTER_ID.cache.amazonaws.com:6380" },
        { "name": "REDIS_TLS",                "value": "true" },
        { "name": "SHUTDOWN_TIMEOUT_MS",      "value": "30000" },
        { "name": "AI_CHAT_TIMEOUT_MS",       "value": "30000" },
        { "name": "OPENAI_TIMEOUT_MS",        "value": "30000" },
        { "name": "VERIFY_TIMEOUT_MS",        "value": "5000" },
        { "name": "QODIQA_KEYS_PATH",         "value": "/opt/qodiqa/data/keys.json" },
        { "name": "QODIQA_AUDIT_LOG",         "value": "/opt/qodiqa/logs/audit.log" },
        { "name": "POLICY_FILE",              "value": "/opt/qodiqa/config/policies.json" }
      ],
      "secrets": [
        {
          "name": "QODIQA_KEY_ENCRYPTION_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/kek"
        },
        {
          "name": "QODIQA_EXECUTION_INVARIANT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/execution-invariant-secret"
        },
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/openai-api-key"
        },
        {
          "name": "QODIQA_CLIENT_ID",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/client-id"
        },
        {
          "name": "REDIS_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:/qodiqa/prod/redis-password"
        }
      ],
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "wget -qO- http://localhost:3000/health || exit 1"
        ],
        "interval": 15,
        "timeout":  5,
        "retries":  3,
        "startPeriod": 30
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group":         "/ecs/qodiqa",
          "awslogs-region":        "REGION",
          "awslogs-stream-prefix": "qodiqa",
          "awslogs-create-group":  "true"
        }
      },
      "stopTimeout": 60
    }
  ]
}
```

**Note on `stopTimeout`:** Set to at least `SHUTDOWN_TIMEOUT_MS / 1000 + 15`
seconds (default 45s; 60s recommended).  ECS sends `SIGTERM` when stopping a
task and waits `stopTimeout` seconds before sending `SIGKILL`.  If `stopTimeout`
is shorter than the shutdown sequence, in-flight requests may be killed mid-flight
and the audit log may have partially written entries (though `fsyncSync` per write
means all completed writes are durable).

---

## Health check integration

ECS uses the `healthCheck` block in the container definition for task placement
and ALB target group health monitoring.

### Container health check vs ALB target group health check

| Check type | Endpoint | Purpose |
|---|---|---|
| Container `healthCheck` | `GET /health` | Task-level — ECS decides if the container is healthy |
| ALB target group | `GET /ready` | Traffic-level — ALB routes traffic only to healthy targets |

Configure the ALB target group with:

```json
{
  "HealthCheckProtocol": "HTTP",
  "HealthCheckPath": "/ready",
  "HealthCheckPort": "3000",
  "HealthyThresholdCount": 2,
  "UnhealthyThresholdCount": 3,
  "HealthCheckIntervalSeconds": 10,
  "HealthCheckTimeoutSeconds": 5
}
```

Using `/ready` for the ALB health check ensures no traffic reaches a pod
during startup, shutdown, or when Redis stores are degraded.  Using `/health`
for the container health check ensures ECS restarts the task only when the
process is truly dead, not when Redis is temporarily unavailable.

---

## Startup validation behavior on ECS

QODIQA's startup sequence on ECS proceeds identically to Kubernetes (see
`docs/deployment/startup-and-probes.md`).  The key ECS-specific considerations are:

1. **Secret injection latency**: Secrets Manager secrets are resolved by the ECS
   agent before the container starts.  Allow 5–15 seconds in the `startPeriod`
   of the `healthCheck` for this resolution.

2. **EFS mount availability**: The EFS file system must be mounted before QODIQA
   starts writing to `/opt/qodiqa/data` or `/opt/qodiqa/logs`.  ECS mounts
   volumes before the container starts, so no init container is needed.

3. **ElastiCache CONFIG GET**: ElastiCache does not support `CONFIG GET`, and a
   failed `CONFIG GET` is treated as unsafe. Since `STRICT_REPLAY_PROTECTION`
   defaults to `true` (as set explicitly in the task definition above), QODIQA
   will refuse to start (`process.exit(1)`) against ElastiCache by default.
   Verify AOF is enabled in the ElastiCache parameter group separately, then
   explicitly set `STRICT_REPLAY_PROTECTION=false` only once you've confirmed
   AOF is active — otherwise leave it at its default (`true`).

---

## Rolling deployments

> **Production runs exactly one task.** The `maximumPercent: 200` example below starts the new task
> while the old one still runs, i.e. two single-node writers dual-writing the same PostgreSQL `audit_chain` — the
> topology the single-writer invariant forbids (`docs/architecture/SINGLE_WRITER_ARCHITECTURE.md`; the boot check
> `assertNoIllegalTopology()` sees only the declared `QODIQA_REPLICA_COUNT`, so it cannot catch an overlapping
> rollout). For the production single-task service use `"minimumHealthyPercent": 0, "maximumPercent": 100` (stop
> the old task before starting the new one — a brief full outage, the same as the Kubernetes single-replica
> StatefulSet). The example below is for non-production multi-task evaluation only.

ECS rolling updates replace tasks one at a time using the deployment configuration
on the ECS service:

```json
{
  "deploymentConfiguration": {
    "minimumHealthyPercent": 100,
    "maximumPercent": 200,
    "deploymentCircuitBreaker": {
      "enable": true,
      "rollback": true
    }
  }
}
```

- `minimumHealthyPercent: 100` — keeps full capacity during the rollout.
- `maximumPercent: 200` — allows doubling capacity to run old and new tasks simultaneously.
- `deploymentCircuitBreaker` — automatically rolls back to the previous task definition if the new tasks fail to reach a healthy state.

**Rolling update sequence:**
1. ECS launches a new task with the updated task definition.
2. The ALB target group health check (`/ready`) must pass for the new task before traffic is shifted.
3. ECS sends `SIGTERM` to an old task, which begins the graceful shutdown sequence.
4. The old task drains in-flight requests and exits cleanly within `stopTimeout` seconds.
5. ECS repeats until all old tasks are replaced.

---

## CloudWatch log retention

```bash
aws logs put-retention-policy \
    --log-group-name /ecs/qodiqa \
    --retention-in-days 90
```

Audit log entries (from `audit.log`) are emitted to the application's stdout log
stream.  For compliance, stream audit entries to a separate log group with a
longer retention policy or to an immutable S3 bucket:

```bash
aws logs create-log-group --log-group-name /qodiqa/audit
aws logs put-retention-policy --log-group-name /qodiqa/audit \
    --retention-in-days 365
```

Wire a CloudWatch Logs subscription filter to route `GATEWAY_ALLOW` and
`GATEWAY_BLOCK` events to the audit log group.

---

## ECS task placement recommendations

- Use `FARGATE_SPOT` capacity for non-production environments to reduce cost.
- Use `FARGATE` (on-demand) for production — spot interruptions cause task
  termination, which may interrupt in-flight enforcement requests.
- Spread tasks across at least two Availability Zones for HA (non-production multi-task evaluation only — production
  runs one task, so there is no gateway HA):

```json
{
  "placementStrategy": [
    { "type": "spread", "field": "attribute:ecs.availability-zone" }
  ]
}
```

---

## Failure recovery

| Failure | ECS behavior | Recovery |
|---|---|---|
| Task OOM kill | ECS restarts the task | Automatic — new task starts fresh |
| Nonce store unavailable/unsafe at startup (default `STRICT_REPLAY_PROTECTION=true`, as set above) | Task fails to start (`process.exit(1)`) | ECS retries with back-off — fix Redis connectivity/AOF; not a degraded start |
| Anomaly or rate-limit store unavailable at startup | Task starts in DEGRADED mode, `/ready` returns 503 | Automatic — stores reconnect; ALB stops routing until `/ready` returns 200 |
| Secrets Manager unavailable | Task fails to start (secret injection blocked by ECS agent) | ECS retries with back-off |
| EFS mount unavailable | Task fails to start | ECS retries with back-off; investigate EFS mount target |
| SIGTERM (graceful stop) | Task drains and exits cleanly within `stopTimeout` | Normal rolling update behavior |

Always configure the deployment circuit breaker with automatic rollback so that
a bad deployment reverts automatically rather than requiring manual intervention.
