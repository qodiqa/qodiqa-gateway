# Installing with Helm and Terraform

> Status: **tested and verified internally** (lint, render in both profiles, kubeconform, an install on a local `kind` cluster — see "What was verified"). The chart is not published; the image repository below is a placeholder until the project's publishing step.

The chart `deploy/helm/qodiqa` renders the gateway in the **distributed topology** (PostgreSQL orders the audit chain, Redis holds replay and rate-limit state), the same hardened pod as `deploy/kubernetes/overlays/distributed`:
non-root, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no service-account token, TLS to PostgreSQL and Redis, MAC keyring and keystore from the cluster. It also renders a migration Job (Helm
hook), a Service, a PodDisruptionBudget, optional HPA / Ingress / NetworkPolicy, and optional ServiceMonitor and PrometheusRule.

## Production profile (default)

**Single node only.** The gateway refuses `QODIQA_DEPLOYMENT_MODE=distributed` in production (the distributed audit chain has no signed checkpoints or anchors yet), so the production profile renders `single-node`, defaults to `replicaCount: 1`, and refuses more replicas at render time. Replicas above one are for the development profile only (the kind verification used 2 and 3).

The chart **never creates production secrets**. Before installing, create in the target namespace:

| What | Name (values) | Content |
| --- | --- | --- |
| Gateway secrets | `secrets.existingSecret` | keys `key-encryption-key`, `client-id`, `redis-password`, `postgres-password`, `postgres-retention-password`, `postgres-system-password`, `postgres-reporting-password`, `postgres-control-password`, `postgres-mig-password`, `postgres-admin-password`, `postgres-mig-role-password`, `postgres-backup-password`, `execution-invariant-secret`, `dsr-pseudonym-pepper`; optional `openai-api-key`, `alert-webhook-url`, `alert-webhook-secret` |
| MAC keyring | `secrets.macKeyringSecret` (default `qodiqa-mac-keyring`) | file `mac-keys.json` made with `node scripts/security/macKeyring.js init` (production never creates it at start: a missing file stops the start) |
| Redis TLS | `secrets.redisTlsSecret` (default `qodiqa-redis-tls`) | `ca.crt`, `client.crt`, `client.key` |
| PostgreSQL TLS CA | `secrets.pgTlsSecret` (optional) | CA for verification |
| Keystore | `keystore.persistence.*` | a `ReadWriteMany` claim for more than one replica (`helm.sh/resource-policy: keep`: the signing keys outlive the release) |

```bash
helm upgrade --install qodiqa deploy/helm/qodiqa -n qodiqa --create-namespace \
  --set image.repository=registry.example.com/qodiqa --set image.digest=sha256:... \
  --set secrets.existingSecret=qodiqa-secrets \
  --set postgres.host=pg.internal --set redis.url=rediss://redis.internal:6380
```

A rendering that would weaken production (no secret named, `postgres.ssl=false`, `redis.tls=false`, `keystore.useEmptyDir`, `createDevSecret`) **fails at template time**. The gateway's own boot rules (`docs/configuration/boot-rules.md`)
are a second, independent check at start.

**Migrations.** The Job `…-migrate-<revision>` runs `node src/infra/postgres/migrate.js` as a `pre-install,pre-upgrade` hook with the migration identity (`migrations.user`, secret key `postgres-mig-password`). The chain creates the runtime
roles with PUBLISHED placeholder passwords, so by default (`migrations.rotateRolePasswords: true`) the Job then sets the real ones from the Secret (app, retention, system, reporting, control, `qodiqa_mig`, `qodiqa_backup`; each at least 24
characters), removes the login of the unused `qodiqa_read`, and runs `scripts/db/role-credentials.js --check`, which fails the Job if any role still accepts its placeholder. This needs an administrative role (`migrations.admin.user`) and fails the render
without one. On a brand-new PostgreSQL cluster the first run needs the bootstrap sequence of `docs/operations/database-role-management.md`. Upgrades: the hook runs first; the new pods start only after the schema is current.

**Values worth knowing.** `replicaCount` (1; the production profile refuses more), `resources`, `autoscaling`, `podDisruptionBudget`, `networkPolicy.providerEgressCidrs` (narrow it), `ingress`, `gateway.env` (any gateway variable, wins over the chart's defaults), `gateway.policies`
(mounted as `policies.json`), `monitoring.serviceMonitor` / `monitoring.prometheusRule` (need the Prometheus Operator CRDs).

## Development profile (local clusters only)

`profile=development` runs `NODE_ENV=development` against plain-text PostgreSQL/Redis with throw-away secrets (`secrets.createDevSecret=true`). **Never for real traffic.** `deploy/helm/qodiqa/ci/` holds the fixtures
(PostgreSQL, Redis with an ACL user, the sandbox AI provider) and `dev-values.yaml` used to verify the chart on kind. From a checkout, with Docker, kind and kubectl (Helm can run from its image: `docker run alpine/helm:3.15.4 ...`):

```bash
kind create cluster --name qodiqa-f11
docker build -t qodiqa:local . && kind load docker-image qodiqa:local --name qodiqa-f11
kubectl create namespace qodiqa
kubectl -n qodiqa create configmap sandbox-provider --from-file=sandboxProvider.js=scripts/dev/sandboxProvider.js
kubectl -n qodiqa apply -f deploy/helm/qodiqa/ci/fixtures.yaml
kubectl -n qodiqa rollout status deploy/pg deploy/redis deploy/sandbox-provider
helm upgrade --install qodiqa deploy/helm/qodiqa -n qodiqa -f deploy/helm/qodiqa/ci/dev-values.yaml --wait --timeout 8m
helm test qodiqa -n qodiqa            # GET /health and /ready from inside the cluster
```

The development values turn on what a throw-away cluster needs and a production one must not: `keystore.provision.enabled` (an init container creates the signing, consent-signer and transparency keys), `QODIQA_CONTROL_PLANE_BACKEND=pg`,
`QODIQA_OPS_MFA_REQUIRED=false`, `apparmor.enabled=false` (Docker Desktop's kernel has no AppArmor and rejects pods that carry the profile), no NetworkPolicy. First credentials (the identities live in PostgreSQL, so every replica sees them). The two secrets are printed once: capture them, they cannot be shown again.

```bash
POD=$(kubectl -n qodiqa get pod -l app.kubernetes.io/component=gateway -o name | head -1)
SIGN_OUT=$(kubectl -n qodiqa exec $POD -c qodiqa -- node scripts/provision-signing-identity.js --name smoke --tenant-id helm-dev-client --environment development)
echo "$SIGN_OUT"                                    # contains the identity id and the sk_... token
QODIQA_SIGN_TOKEN=$(echo "$SIGN_OUT" | grep -o 'sk_[0-9a-f]*' | head -1)
IDENTITY_ID=<the identity id printed above>
OK=$(kubectl -n qodiqa exec $POD -c qodiqa -- node scripts/rbac-bootstrap-key.js | grep -o 'ok_[0-9a-f]*' | head -1)   # QODIQA_API_KEY
kubectl -n qodiqa port-forward svc/qodiqa 18080:80 &
until curl -sf localhost:18080/health >/dev/null; do sleep 1; done          # the port-forward needs a moment
curl -s -X POST localhost:18080/v1/admin/tenants -H "Authorization: Bearer $OK" -H 'content-type: application/json' -d '{"tenantId":"helm-dev-client","name":"Helm dev client"}'
curl -s -X POST localhost:18080/consent -H "Authorization: Bearer $OK" -H 'content-type: application/json' -d "{\"actorId\":\"$IDENTITY_ID\",\"action\":\"local\",\"tenantId\":\"helm-dev-client\",\"lawfulBasis\":\"consent\",\"purpose\":\"smoke test\",\"grantReference\":\"smoke test\"}"
```

SDK smoke tests (all take `QODIQA_BASE_URL=http://localhost:18080`, `QODIQA_SIGN_TOKEN` and `QODIQA_API_KEY=$OK`; each prints one PASS/FAIL line per check and exits 1 on any failure):

```bash
export QODIQA_BASE_URL=http://localhost:18080 QODIQA_SIGN_TOKEN QODIQA_API_KEY=$OK
npm --prefix sdk/javascript ci && npm --prefix sdk/javascript run build   # smoke.js and guard-smoke.js load sdk/javascript/dist (git-ignored); the guard also needs express in the repo root (npm ci)
node deploy/helm/qodiqa/ci/sdk-smoke/smoke.js
node deploy/helm/qodiqa/ci/sdk-smoke/guard-smoke.js
python deploy/helm/qodiqa/ci/sdk-smoke/smoke.py                            # needs sdk/python dependencies (pip install ./sdk/python)
# Go and Java have no toolchain on most hosts; run them in their images, with --network host (or the cluster network) so they reach the port-forward:
docker run --rm --network host -v "$PWD/sdk/go:/w" -w /w -e QODIQA_BASE_URL -e QODIQA_SIGN_TOKEN -e QODIQA_API_KEY golang:1.22 go run ./cmd/smoke
docker run --rm --network host -v "$PWD/sdk/java:/w" -w /w -e QODIQA_BASE_URL -e QODIQA_SIGN_TOKEN -e QODIQA_API_KEY maven:3-eclipse-temurin-21 sh -c "mvn -q -DskipTests compile test-compile && mvn -q dependency:build-classpath -Dmdep.outputFile=/tmp/cp >/dev/null && java -cp target/classes:target/test-classes:$(cat /tmp/cp) dev.qodiqa.sdk.Smoke"
```

Notes: the fixtures (`ci/fixtures.yaml`) reference the image `qodiqa:local` with `pullPolicy: Never`, so the image you build and load must be tagged exactly `qodiqa:local` (any other tag ends in `ErrImageNeverPull` on the sandbox provider). The migration Job pod is deleted when it succeeds, so its log (which shows the role-password rotation and the placeholder proof) is only readable while it runs: `kubectl -n qodiqa logs -f job/<release>-migrate` during the install, or `helm get hooks`.

## Terraform

`deploy/terraform/modules/qodiqa` wraps the chart (`helm_release`) and can create the namespace (Pod Security `restricted`) and the Secret (`secret_values` puts secrets into the Terraform state: protect it, or use
`existing_secret`). `deploy/terraform/examples/kind` is a local example. The module does not create the database, Redis, the keyring or TLS material.

## What was verified (and what was not)

- `helm lint`, `helm template` in both profiles with every optional feature on, `kubeconform -strict` (custom resources skipped), `terraform validate` and `terraform fmt -check`.
- An install on a local kind cluster in the **development** profile, an upgrade (`replicaCount` 2 → 3, migration hook re-run; the independent re-run could not confirm the third replica Ready before its Docker engine hung), `helm test`, and the JavaScript, Python, Go and Java SDKs plus the Express artifact guard run against the installed gateway (sign, offline verification, request-hash binding, chat through the sandbox provider, replay refusal, a generic operation, error mapping); the record is.
- **Not verified:** the production profile on a real cluster (TLS PostgreSQL/Redis, a ReadWriteMany volume, NetworkPolicy enforcement — kind's default CNI does not enforce policies), the Prometheus Operator resources against a live operator, upgrades across chart versions.
