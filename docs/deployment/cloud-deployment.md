# Cloud Deployment Security

This document covers network isolation, secret management, certificate
management, logging, monitoring, and high-availability for QODIQA deployments
on AWS, Azure, GCP, and Kubernetes-native environments.

Vendor-neutral principles are stated first.  Cloud-specific examples follow.

---

## Vendor-neutral principles

### 1. Never expose QODIQA directly to the internet

QODIQA is an internal enforcement gateway.  Public internet traffic should reach
it only through an authenticated load balancer or API gateway that:

- Terminates TLS from the client
- Authenticates the caller (API key, OAuth, mTLS)
- Rate-limits at the edge before requests reach QODIQA

The QODIQA port (default 3000) must have no inbound security group rule from
`0.0.0.0/0`.

### 2. Treat Redis as an internal-only resource

Redis stores security-critical nonce, anomaly, and rate-limit state.  It must:

- Have no public IP
- Accept connections only from QODIQA's security group or subnet
- Require authentication (REDIS_PASSWORD or ACL)
- Use TLS in transit (see `docs/deployment/redis-tls.md`)
- Have persistence enabled (see `docs/deployment/redis-persistence.md`)

### 3. Terminate TLS at the load balancer for inbound traffic

Clients connect to the load balancer over HTTPS.  The load balancer forwards
requests to QODIQA over HTTP within the private network.  This pattern:

- Centralises certificate management at one point
- Allows QODIQA to run without a TLS listener
- Lets the LB handle certificate rotation without application restarts

If your threat model requires end-to-end encryption (traffic between the LB and
QODIQA must also be encrypted), add a TLS listener to QODIQA and configure the
LB for passthrough or backend HTTPS.  This is rarely necessary within a VPC with
proper security group isolation.

### 4. Separate secret management from configuration management

Environment variables are configuration.  Secrets are not.  Use a dedicated
secret management service that:

- Enforces access control on each secret independently
- Logs every access to a secret
- Supports automatic rotation
- Does not store secrets in the application's environment at rest

### 5. Use a dedicated QODIQA IAM/service identity

QODIQA's cloud identity (IAM role, service account, managed identity) should
have exactly the permissions it needs:

- Read access to its own secrets
- No access to secrets belonging to other services
- No admin permissions of any kind
- No ability to assume other roles

---

## Network isolation

### VPC / subnet design

```
Internet
    │
    ▼
[Load Balancer / API Gateway]    ← public subnet, TLS termination
    │  (private network, HTTP)
    ▼
[QODIQA]                         ← private subnet, no public IP
    │  (private network, rediss://)
    ▼
[Redis]                          ← private subnet (or managed cache subnet group)
```

Minimum security group rules:

| Resource | Inbound | Outbound |
|---|---|---|
| Load Balancer | 443 from 0.0.0.0/0 | 3000 to QODIQA SG |
| QODIQA | 3000 from LB SG only | 6380 to Redis SG; 443 to the enabled AI provider hostname(s) — see below |
| Redis | 6380 from QODIQA SG only | denied |

### DNS

- Use private DNS for inter-service communication (`redis.internal`, not a public FQDN).
- Never resolve Redis by public IP.

### Egress filtering

The outbound destination(s) QODIQA needs depend on which of the six providers are enabled
(`services/providers/config.js` — a provider is enabled by the presence of its API key or, for
`llama`/`local`, its base URL). For the four commercial providers, the base URL is hardcoded
(or, for `mistral`, allowlist-validated) and checked against the SSRF policy at startup —
QODIQA will only ever connect to the hostname for a provider it has enabled:

| Provider | Hostname (enabled by) |
|---|---|
| `openai` | `api.openai.com:443` (`OPENAI_API_KEY`) |
| `anthropic` | `api.anthropic.com:443` (`ANTHROPIC_API_KEY`) |
| `gemini` | `generativelanguage.googleapis.com:443` (`GEMINI_API_KEY`) |
| `mistral` | `api.mistral.ai:443` by default, or the host in `MISTRAL_BASE_URL` if overridden (`MISTRAL_API_KEY`) |
| `llama` | Operator-configured host in `LLAMA_BASE_URL` — may be a public cloud-hosted endpoint (e.g. Groq, Together AI) or a private-network address |
| `local` | Operator-configured host in `LOCAL_BASE_URL` — typically a private-network or loopback address (e.g. Ollama on `localhost:11434`) |

If your environment uses an egress proxy or firewall, allow only the hostnames for the
provider(s) you have actually enabled. A single-provider OpenAI deployment, for example,
needs only:

```
api.openai.com:443   (OpenAI API)
```

`llama` and `local` deployments should scope egress to the specific operator-controlled
endpoint rather than opening egress broadly, since QODIQA's SSRF policy deliberately permits
private-network destinations for these two providers (see `docs/security/THREAT_MODEL.md`,
Boundary 5).

Block all other egress from QODIQA by default.  Redis and internal services are
within the VPC and do not require public egress.

### Kubernetes topology overlays

`deploy/kubernetes/` ships two mutually exclusive execution topologies as
separate Kustomize overlays rather than one combined manifest set (a prior
defect had both applying simultaneously against the same Service selector —
see `deploy/kubernetes/kustomization.yaml`'s header comment):

| Overlay | Workload | Audit-chain ordering authority |
|---|---|---|
| `overlays/single-node/` (small production) | StatefulSet, **replicas: 1**, exclusive audit-log volume, PG enabled as durable evidence store + mirror | Process-local, in-memory |
| `overlays/distributed/` | Deployment, freely scalable — **refused in production until** | PostgreSQL row lock (`QODIQA_AUDIT_ORDERING_MODE=distributed`, ) |

Deploy exactly one per namespace/cluster:

```bash
kubectl apply -k deploy/kubernetes/overlays/single-node/
# — or —
kubectl apply -k deploy/kubernetes/overlays/distributed/
```

Both overlays share ingress/Redis/OpenAI/DNS egress rules from
`deploy/kubernetes/base/networkpolicy.yaml`. Both additionally require
egress to PostgreSQL on port 5432 — each provides its own
`networkpolicy-postgres.yaml`, scoped to its own `topology:` pod label so
neither can widen egress for the other. If PostgreSQL is an external/managed instance (RDS,
Cloud SQL, Azure Database for PostgreSQL) rather than an in-cluster Service,
replace that NetworkPolicy's `podSelector` with an `ipBlock` covering the
database's CIDR, following the same scoping principle as the OpenAI egress
rule above — see that file's header comment for the exact adjustment.

Both topology overlays default to the `local` (raw env-var) KEK mode.
Previously, the Dockerfile's default `CMD ["node", "server.js"]` never
initialized an external KMS provider even if `QODIQA_KMS_PROVIDER` was set in
a ConfigMap — only `node start.js` did (see Finding D). As of items 21/22,
**both entrypoints are equivalent for KMS initialization purposes**:
`node server.js` (the Dockerfile's default command) now initializes
whichever backend `QODIQA_KMS_PROVIDER` selects, exactly as `node start.js`
already did. The reference overlays' `command: ["node", "start.js"]` patch
remains a fully valid choice going forward (`start.js`'s own behavior is
unchanged by this fix) — it is simply no longer the *only* way to make
`QODIQA_KMS_PROVIDER` take effect, not something being deprecated or phased
out.
For Vault Transit or PKCS#11 HSM-backed key custody (/ SECRETS-K8S-2
remediation — untested against a real Vault or HSM; only mocks and local emulators), see the reference overlays at
`deploy/kubernetes/overlays/examples/vault-transit/` and `.../examples/hsm/`,
which base on `overlays/single-node/` and patch the container with that
provider's required credentials — see
`deploy/kubernetes/overlays/examples/README.md`.

---

## AWS

### Compute

Use **ECS Fargate** (serverless containers) or **EKS** (Kubernetes).  Avoid
EC2-based deployments unless you have a specific requirement — Fargate and EKS
reduce the attack surface by eliminating the EC2 instance management layer.

### Networking

```
AWS VPC (e.g. 10.0.0.0/16)
├── Public subnets (10.0.0.0/24, 10.0.1.0/24)
│   └── Application Load Balancer
└── Private subnets (10.0.2.0/24, 10.0.3.0/24)
    ├── ECS/EKS — QODIQA tasks
    └── ElastiCache subnet group — Redis
```

**Security groups:**

```
# ALB security group
aws ec2 create-security-group --group-name alb-qodiqa --description "ALB for QODIQA"
aws ec2 authorize-security-group-ingress --group-id sg-ALB \
    --protocol tcp --port 443 --cidr 0.0.0.0/0

# QODIQA task security group
aws ec2 create-security-group --group-name qodiqa-tasks --description "QODIQA ECS tasks"
aws ec2 authorize-security-group-ingress --group-id sg-QODIQA \
    --protocol tcp --port 3000 --source-group sg-ALB

# Redis security group
aws ec2 create-security-group --group-name qodiqa-redis --description "ElastiCache for QODIQA"
aws ec2 authorize-security-group-ingress --group-id sg-REDIS \
    --protocol tcp --port 6380 --source-group sg-QODIQA
```

### Secrets — AWS Secrets Manager

This example uses `openai` as the enabled provider; substitute the secret name and value for
whichever provider(s) you enable instead (`anthropic-api-key`, `gemini-api-key`,
`mistral-api-key`, `llama-base-url`/`llama-api-key`, or `local-base-url`/`local-api-key`).

```bash
# Store each secret individually for fine-grained IAM control
aws secretsmanager create-secret --name qodiqa/kek \
    --secret-string "$(openssl rand -hex 32)"

aws secretsmanager create-secret --name qodiqa/sign-token \
    --secret-string "$(openssl rand -hex 32)"

aws secretsmanager create-secret --name qodiqa/openai-api-key \
    --secret-string "sk-..."

aws secretsmanager create-secret --name qodiqa/redis-password \
    --secret-string "$(openssl rand -base64 32)"
```

**IAM policy for QODIQA task role** (least privilege):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/kek-*",
        "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/sign-token-*",
        "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/openai-api-key-*",
        "arn:aws:secretsmanager:REGION:ACCOUNT:secret:qodiqa/redis-password-*"
      ]
    }
  ]
}
```

### Certificate management — AWS ACM

- Issue the ALB's public TLS certificate from AWS Certificate Manager (free, auto-renews).
- Issue Redis TLS certificates from ACM Private CA or an internal CA.
- Rotate Redis client certificates before they expire; use cert-manager in EKS or
  a Lambda rotation function for Fargate.

### Redis — ElastiCache

```bash
aws elasticache create-replication-group \
    --replication-group-id qodiqa-redis \
    --replication-group-description "QODIQA Redis" \
    --engine redis \
    --engine-version 7.0 \
    --cache-node-type cache.t3.medium \
    --num-cache-clusters 2 \
    --transit-encryption-enabled \
    --auth-token "$(aws secretsmanager get-secret-value --secret-id qodiqa/redis-password --query SecretString --output text)" \
    --at-rest-encryption-enabled \
    --cache-parameter-group-name qodiqa-redis-params \
    --security-group-ids sg-REDIS \
    --cache-subnet-group-name qodiqa-private
```

Create a parameter group with AOF enabled:

```bash
aws elasticache create-cache-parameter-group \
    --cache-parameter-group-name qodiqa-redis-params \
    --cache-parameter-group-family redis7

aws elasticache modify-cache-parameter-group \
    --cache-parameter-group-name qodiqa-redis-params \
    --parameter-name-values \
        ParameterName=appendonly,ParameterValue=yes \
        ParameterName=appendfsync,ParameterValue=everysec
```

Note: ElastiCache does not support the Redis `CONFIG GET` command from clients,
and a failed `CONFIG GET` is treated as unsafe. Since `STRICT_REPLAY_PROTECTION`
defaults to `true`, QODIQA will refuse to start (`process.exit(1)`) against
ElastiCache by default rather than merely warning. Confirm AOF is active in
the parameter group first, then explicitly set `STRICT_REPLAY_PROTECTION=false`
to bypass the unverifiable check — leaving the variable unset does not
achieve this, since unset still means `true`.

### Logging — CloudWatch

```bash
aws logs create-log-group --log-group-name /ecs/qodiqa
aws logs put-retention-policy --log-group-name /ecs/qodiqa --retention-in-days 90
```

Set a metric filter for security events:

```bash
aws logs put-metric-filter \
    --log-group-name /ecs/qodiqa \
    --filter-name QodiqaSecurityEvents \
    --filter-pattern '{ $.level = "WARN" || $.level = "ERROR" || $.level = "FATAL" }' \
    --metric-transformations \
        metricName=QodiqaSecurityEventCount,metricNamespace=QODIQA,metricValue=1
```

---

## Azure

### Compute

Use **Azure Container Apps** or **AKS**.  Container Apps is recommended for
simpler deployments; AKS for Kubernetes-native workloads.

### Networking

```
Azure VNet (e.g. 10.0.0.0/16)
├── Public subnet (10.0.0.0/24)
│   └── Application Gateway / Front Door
└── Private subnet (10.0.1.0/24)
    ├── Container Apps environment / AKS node pool
    └── Azure Cache for Redis (private endpoint)
```

Use a **Private Endpoint** for Azure Cache for Redis so traffic never leaves
the VNet:

```bash
az network private-endpoint create \
    --name qodiqa-redis-pe \
    --resource-group qodiqa-rg \
    --vnet-name qodiqa-vnet \
    --subnet private-subnet \
    --private-connection-resource-id /subscriptions/.../providers/Microsoft.Cache/Redis/qodiqa-redis \
    --group-ids redisCache \
    --connection-name qodiqa-redis-connection
```

### Secrets — Azure Key Vault

```bash
az keyvault create --name qodiqa-kv --resource-group qodiqa-rg \
    --sku standard --enable-purge-protection true

az keyvault secret set --vault-name qodiqa-kv --name kek \
    --value "$(openssl rand -hex 32)"

az keyvault secret set --vault-name qodiqa-kv --name sign-token \
    --value "$(openssl rand -hex 32)"
```

Assign the QODIQA managed identity read access to its secrets only:

```bash
az keyvault set-policy --name qodiqa-kv \
    --object-id $(az identity show --name qodiqa-identity --query principalId -o tsv) \
    --secret-permissions get
```

### Certificate management — Azure Key Vault + App Service Certificate

- Store TLS certificates in Azure Key Vault.
- Use **Azure Key Vault Certificate Authority** or an imported certificate for Redis TLS.
- Use the AKS Secret Store CSI Driver to mount Key Vault secrets as Kubernetes secrets.

### Redis — Azure Cache for Redis

Use **Premium tier** for AOF persistence support:

```bash
az redis create --name qodiqa-redis --resource-group qodiqa-rg \
    --sku Premium --vm-size P1 \
    --redis-version 7 \
    --enable-non-ssl-port false  # TLS only
```

Enable AOF persistence in the Azure Portal under **Data persistence** →
**AOF persistence** → **AOF — fsync every second**.

---

## GCP

### Compute

Use **Cloud Run** (serverless) or **GKE Autopilot**.  Cloud Run enforces many
container security properties by default (non-root, read-only filesystem option).

### Networking

```
GCP VPC
├── Cloud Load Balancing (external HTTPS)
└── Private subnet
    ├── Cloud Run / GKE workloads
    └── Memorystore for Redis (PSC private endpoint)
```

Use **Private Service Connect** to keep Memorystore traffic within the VPC:

```bash
gcloud redis instances create qodiqa-redis \
    --size=1 \
    --region=us-central1 \
    --redis-version=redis_7_0 \
    --network=projects/PROJECT/global/networks/qodiqa-vpc \
    --connect-mode=PRIVATE_SERVICE_ACCESS \
    --tier=STANDARD_HA \
    --transit-encryption-mode=SERVER_AUTHENTICATION
```

**Important**: GCP Memorystore for Redis does not support AOF persistence.
QODIQA can connect to Memorystore with TLS, but `STRICT_REPLAY_PROTECTION`
**defaults to `true`** and will fail startup by default because AOF cannot be
confirmed — this is not something you opt into, it is the out-of-the-box
behavior against Memorystore. Options:

1. Run a self-managed Redis instance on GKE with AOF enabled (recommended for
   strict replay protection) — keeps `STRICT_REPLAY_PROTECTION` at its
   default (`true`).
2. Explicitly set `STRICT_REPLAY_PROTECTION=false` to accept the reduced
   guarantee and monitor `REPLAY_PROTECTION_DEGRADED` events.

### Secrets — Secret Manager

```bash
echo -n "$(openssl rand -hex 32)" | gcloud secrets create qodiqa-kek \
    --data-file=- --replication-policy=automatic

echo -n "$(openssl rand -hex 32)" | gcloud secrets create qodiqa-sign-token \
    --data-file=- --replication-policy=automatic
```

Grant the QODIQA service account access to its own secrets only:

```bash
gcloud secrets add-iam-binding qodiqa-kek \
    --member="serviceAccount:qodiqa@PROJECT.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

**Workload Identity** (GKE): bind the Kubernetes service account to the GCP
service account so pods access Secret Manager without a key file:

```bash
gcloud iam service-accounts add-iam-binding qodiqa@PROJECT.iam.gserviceaccount.com \
    --role=roles/iam.workloadIdentityUser \
    --member="serviceAccount:PROJECT.svc.id.goog[production/qodiqa]"
```

---

## Ingress security

### TLS termination

Always terminate external TLS at the load balancer.  Use a managed certificate
service to handle renewal automatically:

| Platform | Managed certificates |
|---|---|
| AWS | ACM with ALB |
| Azure | App Service Certificate / Key Vault with Application Gateway |
| GCP | Google-managed certificates with Cloud Load Balancing |
| Kubernetes | cert-manager with Let's Encrypt |

### API Gateway authentication

QODIQA's `/ai/chat` and `/sign` endpoints should be behind an API gateway that
enforces authentication.  The `/sign` endpoint has its own token-based
authentication, but adding a network-level authentication layer (API key at the
gateway) provides defense in depth.

### DDoS and rate limiting at the edge

Configure edge-level rate limiting at the load balancer or API gateway before
requests reach QODIQA.  QODIQA enforces its own rate limits internally, but
reducing the volume of requests that reach QODIQA protects Redis and reduces
the blast radius of a volumetric attack.

---

## Secret rotation guidance

1. **Redis password**: rotate every 90 days or after any suspected exposure.
   Update the secret in your secret manager, update `REDIS_PASSWORD` in the
   deployment, and perform a rolling restart.  Redis supports password rotation
   via ACLs without disconnecting existing connections.

2. **`QODIQA_EXECUTION_INVARIANT_SECRET`**: rotate every 90 days or after any
   suspected exposure. The value is cached for the process lifetime after first
   use, so the new secret takes effect only after a rolling restart.

3. **Signing identities** (there is no `QODIQA_SIGN_TOKEN` shared secret to
   rotate): re-issue a compromised or expiring identity's key via `POST
   /signing-identities/:id/api-key` and revoke/disable the old one — no
   restart required, resolved per-request from the store.

4. **`QODIQA_KEY_ENCRYPTION_KEY`**: rotation requires re-encrypting the key
   store.  Plan this carefully.  The KEK should only change if it is suspected
   to be compromised.  Normal operational rotation is not required because the
   KEK protects data at rest; the data it protects (Ed25519 signing keys) is
   rotated separately via `rotateKey()`.

5. **TLS certificates**: automate renewal.  Use cert-manager (Kubernetes),
   ACM (AWS), or equivalent.  Monitor certificate expiry with an alerting rule
   30 days before expiry.

6. **AI provider credentials** (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`,
   `MISTRAL_API_KEY`, `LLAMA_API_KEY`, `LOCAL_API_KEY`): rotate immediately on any suspected
   exposure. Commercial provider keys (OpenAI, Anthropic, Gemini, Mistral) can be revoked and
   replaced in the respective provider's dashboard with no service downtime — the new key
   takes effect on the next request after deployment. For `llama`/`local`, rotate credentials
   according to the operator-controlled endpoint's own auth mechanism.

---

## Logging recommendations

All QODIQA log output is structured JSON emitted to stdout/stderr.  Collect it
with your platform's log driver and route to a SIEM or log analysis service.

**Minimum retention**: 90 days for all log streams.

**Events to alert on immediately:**

| Event | Severity | Action |
|---|---|---|
| `FATAL` level events | Critical | Page on-call — service cannot start |
| `REDIS_AUTH_REJECTED` | Critical | Credential mismatch or compromise |
| `REDIS_TLS_FAILED` | Critical | Certificate issue — replay protection degraded |
| `REPLAY_PROTECTION_DEGRADED` | High | Redis unavailable or persistence unsafe |
| `SECRET_VALIDATION_FATAL` | Critical | Placeholder secrets in production |
| `GATEWAY_BLOCK` with high frequency | Medium | Potential attack pattern |
| `PROVIDER_AUTH_FAILED` | High | The enabled provider's API key may be invalid or expired (reported per-provider in the `PROVIDER_EXECUTION` event's `provider` field) |
| `NO_PROVIDER_CONFIGURED` | Critical | No AI provider is enabled — service cannot start |

**Audit log shipping**: ship `audit.log` separately from application logs.
The audit log is cryptographically chained and must be shipped in append-only
mode to preserve chain integrity.  Do not truncate or rotate it without
verifying the chain first.

---

## Monitoring recommendations

Expose `/metrics` to your Prometheus scrape job.  Key metrics to alert on:

| Metric | Alert threshold | Meaning |
|---|---|---|
| `redis_store_up{store="nonce"}` | < 1 for > 30s | Replay protection degraded |
| `redis_store_up{store="anomaly"}` | < 1 for > 30s | Anomaly detection degraded |
| `redis_store_up{store="rate_limit"}` | < 1 for > 30s | Rate limiting degraded |
| `execution_integrity_full` | < 1 for > 60s | All-stores degraded |
| HTTP error rate on `/ai/chat` | > 5% for > 1m | Policy enforcement or service issue |
| Response p99 on `/ai/chat` | > 10s | Provider or enforcement latency |

---

## Backup recommendations

| Asset | Backup method | Frequency |
|---|---|---|
| `data/keys.json` | Snapshot to encrypted object storage | Daily + after every key rotation |
| `audit.log` | Stream to write-once storage (S3 Object Lock, GCS with retention) | Continuous |
| `policies.json` | Version control (GitOps) | Every change |
| Redis nonce state | AOF persistence — no additional backup needed | Continuous via AOF |

The key store must be backed up with the KEK that encrypted it.  Store both
the encrypted key store backup and the KEK backup in **separate** custody (the KEK never sits with the
encrypted key-store backup it protects; 2026-10-06).
Test key recovery annually.

---

## High availability

### QODIQA

**No HA topology is supported in production today.** The supported shape is one replica (single-node overlay,
`replicas: 1`, a correctness bound); a rollout is a brief full outage. Multiple replicas need distributed mode,
which production refuses until and a single-node
replica count above 1 is refused at boot (`assertNoIllegalTopology()`). No HA deployment has been exercised
. Redis/PostgreSQL HA below protects dependencies only.

### Redis

Use a Redis deployment with:

- **Primary + replica**: one primary handles writes, one or more replicas provide
  read scaling and automatic failover.
- **Sentinel or Cluster**: automatic failover without manual intervention.
- **AOF on both primary and replica**: ensures nonce state survives primary
  failover without replay window.

**Failover impact**: a Redis primary failover causes a brief period where the
nonce store is unavailable.  During this period QODIQA blocks all execution
requests (fail-closed).  After the replica is promoted and QODIQA reconnects,
full enforcement resumes.  The maximum outage window equals the Redis failover
time (typically < 10 seconds with Sentinel).

Do not use Redis Cluster for nonce storage unless you pin nonces to a single
shard (use a hash tag `{qodiqa}:req:v2:...`).  Cross-slot operations across
shards can cause subtle consistency issues.
