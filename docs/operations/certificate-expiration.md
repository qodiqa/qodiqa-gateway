# QODIQA Certificate Expiration Runbook

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Certificate Expiration Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering / Security |
| Audience | SRE, Security Engineer, On-Call |
| Classification | Internal — Operational |
| Last Updated | 2026-07-03 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Expiration Monitoring](#2-expiration-monitoring)
3. [Planned Certificate Renewal](#3-planned-certificate-renewal)
4. [Certificate Rotation Procedure](#4-certificate-rotation-procedure)
5. [Renewal Verification](#5-renewal-verification)
6. [Rollback Procedure](#6-rollback-procedure)
7. [Emergency Certificate Replacement](#7-emergency-certificate-replacement)
8. [Validation Checklist](#8-validation-checklist)

---

## 1. Overview

QODIQA uses TLS certificates in two places:
1. **Redis mTLS** — mutual TLS between QODIQA and Redis (client and server certificates).
2. **PostgreSQL TLS** — TLS between QODIQA and PostgreSQL (client certificate when `QODIQA_PG_SSL=true`).

Certificate expiration in either location causes QODIQA to lose connectivity to the dependency:
- **Redis cert expiry:** `qodiqa_execution_integrity_full{}` drops to 0; all enforcement requests fail (fail-closed).
- **PostgreSQL cert expiry:** Audit chain PostgreSQL sync fails; enforcement continues (file-authoritative).

Both scenarios require certificate renewal within the renewal window to avoid operational impact.

**Renewal policy:**
- Begin renewal when a certificate has **≤ 30 days** remaining.
- Complete renewal when a certificate has **≤ 14 days** remaining.
- Emergency replacement applies when a certificate has **expired or has ≤ 72 hours** remaining with no planned renewal in progress.

---

## 2. Expiration Monitoring

### 2.1 Manual Expiration Check

Run this check daily as part of operational health checks:

```bash
#!/bin/bash
# Check all QODIQA TLS certificate expiration dates

check_cert() {
  local label="$1"
  local cert_path="$2"
  
  if [[ ! -f "$cert_path" ]]; then
    echo "MISSING: $label ($cert_path)"
    return
  fi
  
  EXPIRY_STR=$(openssl x509 -enddate -noout -in "$cert_path" | cut -d= -f2)
  EXPIRY_EPOCH=$(date -d "$EXPIRY_STR" +%s)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
  
  if [[ $DAYS_LEFT -lt 0 ]]; then
    echo "EXPIRED: $label — expired $((DAYS_LEFT * -1)) days ago"
  elif [[ $DAYS_LEFT -le 14 ]]; then
    echo "CRITICAL: $label — $DAYS_LEFT days remaining (renew immediately)"
  elif [[ $DAYS_LEFT -le 30 ]]; then
    echo "WARNING: $label — $DAYS_LEFT days remaining (begin renewal)"
  else
    echo "OK: $label — $DAYS_LEFT days remaining"
  fi
}

check_cert "Redis CA certificate" "$REDIS_TLS_CA"
check_cert "Redis client certificate" "$REDIS_TLS_CERT"
check_cert "PostgreSQL CA certificate" "$QODIQA_PG_SSL_CA"
check_cert "PostgreSQL client certificate" "$QODIQA_PG_SSL_CERT"
```

### 2.2 Prometheus Alert Rules

Configure these Prometheus alert rules for automatic expiration monitoring:

```yaml
# prometheus-rules/qodiqa-certs.yaml
groups:
- name: qodiqa_certificate_expiry
  rules:
  - alert: QodiqaRedisCertExpiringSoon
    expr: |
      (
        probe_ssl_earliest_cert_expiry{job="qodiqa-redis-tls"} - time()
      ) / 86400 < 30
    for: 5m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "QODIQA Redis TLS certificate expiring in {{ $value | humanizeDuration }}"
      description: "Certificate renewal required within 30 days to prevent enforcement downtime."

  - alert: QodiqaRedisCertCritical
    expr: |
      (
        probe_ssl_earliest_cert_expiry{job="qodiqa-redis-tls"} - time()
      ) / 86400 < 14
    for: 5m
    labels:
      severity: critical
      team: platform
    annotations:
      summary: "QODIQA Redis TLS certificate expires in {{ $value | humanizeDuration }}"
      description: "IMMEDIATE ACTION REQUIRED: Redis mTLS cert expiry will cause enforcement to fail-closed."
```

### 2.3 Kubernetes Certificate Monitoring with cert-manager

If using cert-manager for certificate lifecycle management:

```yaml
# Certificate resource managed by cert-manager (recommended)
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: redis-client-tls
  namespace: qodiqa
spec:
  secretName: redis-client-tls-secret
  duration: 8760h  # 1 year
  renewBefore: 720h  # Renew 30 days before expiry
  dnsNames:
  - qodiqa.qodiqa.svc.cluster.local
  issuerRef:
    name: qodiqa-internal-ca
    kind: ClusterIssuer
```

With cert-manager, certificates are automatically renewed. QODIQA pods must be restarted to pick up the new certificate from the Kubernetes Secret.

---

## 3. Planned Certificate Renewal

### 3.1 Renewal Timeline

| Day | Action |
|-----|--------|
| T-30 | Warning alert fires; begin renewal process |
| T-21 | Generate new certificate; test in staging |
| T-14 | Rotate certificate in production |
| T-7 | Verify old certificate is no longer used |
| T-0 | Old certificate expires (should be decommissioned) |

### 3.2 Certificate Generation

#### Using Internal CA (cfssl)

```bash
# Generate a new Redis client certificate
CERT_DIR="/opt/qodiqa/certs"
TIMESTAMP=$(date +%Y%m%d)

# Create CSR configuration
cat > /tmp/redis-client-csr.json << EOF
{
  "CN": "qodiqa-redis-client-${TIMESTAMP}",
  "key": {
    "algo": "ecdsa",
    "size": 256
  },
  "names": [
    {
      "O": "QODIQA Platform",
      "OU": "Infrastructure"
    }
  ]
}
EOF

# Sign with internal CA
cfssl gencert \
  -ca="${CERT_DIR}/ca.pem" \
  -ca-key="${CERT_DIR}/ca-key.pem" \
  -config="${CERT_DIR}/ca-config.json" \
  -profile=client \
  /tmp/redis-client-csr.json | cfssljson -bare /tmp/redis-client-new

# Verify the new certificate
openssl x509 -text -noout -in /tmp/redis-client-new.pem | \
  grep -E 'Subject:|Not Before:|Not After:|Issuer:'
```

#### Using Let's Encrypt (for external-facing HTTPS only)

```bash
# QODIQA Redis and PostgreSQL certs are internal — do NOT use Let's Encrypt
# Let's Encrypt is only appropriate for the HTTPS ingress certificate
certbot renew --cert-name qodiqa-ingress
```

---

## 4. Certificate Rotation Procedure

### 4.1 Backup Current Certificates

```bash
CERT_BACKUP_DIR="/opt/qodiqa/backups/certs/certs-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$CERT_BACKUP_DIR"

cp "$REDIS_TLS_CERT" "$CERT_BACKUP_DIR/redis-client.crt"
cp "$REDIS_TLS_KEY" "$CERT_BACKUP_DIR/redis-client.key"
cp "$REDIS_TLS_CA" "$CERT_BACKUP_DIR/redis-ca.crt"

[[ "$QODIQA_PG_SSL" == "true" ]] && {
  cp "$QODIQA_PG_SSL_CERT" "$CERT_BACKUP_DIR/pg-client.crt"
  cp "$QODIQA_PG_SSL_KEY" "$CERT_BACKUP_DIR/pg-client.key"
  cp "$QODIQA_PG_SSL_CA" "$CERT_BACKUP_DIR/pg-ca.crt"
}

echo "Certificate backup: $CERT_BACKUP_DIR"
```

### 4.2 Redis mTLS Certificate Rotation

Redis mTLS requires both the Redis server and QODIQA client certificates to be trusted by the CA.

**Step 1: Update Redis server to trust both old and new CA (if CA is rotating)**

```bash
# During transition, configure Redis to accept connections from both old and new client certs
# This requires a Redis config update and reload (not QODIQA)
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" \
  CONFIG REWRITE
```

**Step 2: Update the new client certificate in Kubernetes Secret**

```bash
# Kubernetes
kubectl create secret generic redis-client-tls \
  --from-file=tls.crt=/tmp/redis-client-new.pem \
  --from-file=tls.key=/tmp/redis-client-new-key.pem \
  --from-file=ca.crt="$REDIS_TLS_CA" \
  -n qodiqa \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Step 3: Trigger rolling restart of QODIQA to pick up the new cert**

```bash
kubectl rollout restart deployment/qodiqa -n qodiqa
kubectl rollout status deployment/qodiqa -n qodiqa --timeout=120s
```

**Step 4: Verify Redis connectivity with new cert**

```bash
# Test with the new certificate
redis-cli \
  --tls \
  --cacert "$REDIS_TLS_CA" \
  --cert /tmp/redis-client-new.pem \
  --key /tmp/redis-client-new-key.pem \
  -u "$REDIS_URL" \
  PING
# Expected: PONG
```

**Step 5: Verify QODIQA Redis stores are connected**

```bash
# /metrics is ops-authenticated (src/app.js:179): OPS_AUTH_HEADER_FILE is a 0600 file holding one line
# "Authorization: Bearer <operator API key>" (curl -H @file keeps the key out of argv; docs/operations/deployment-runbook.md §8).
curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep redis_store_up
# All three stores must return 1
curl -sf http://localhost:3000/ready
# Expected: 200 {"status":"ready"}
```

### 4.3 PostgreSQL TLS Certificate Rotation

```bash
# Update PostgreSQL client cert in Kubernetes Secret
kubectl create secret generic pg-client-tls \
  --from-file=tls.crt=/tmp/pg-client-new.pem \
  --from-file=tls.key=/tmp/pg-client-new-key.pem \
  --from-file=ca.crt="$QODIQA_PG_SSL_CA" \
  -n qodiqa \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart QODIQA
kubectl rollout restart deployment/qodiqa -n qodiqa
kubectl rollout status deployment/qodiqa -n qodiqa --timeout=120s

# Verify PostgreSQL connectivity
psql "$QODIQA_PG_URL" -c "SELECT 1;" && echo "PG connectivity: OK"
```

---

## 5. Renewal Verification

### 5.1 Post-Rotation Certificate Verification

```bash
# Verify the running pods are using the new certificate
kubectl exec -it <pod-name> -n qodiqa -- \
  openssl s_client -connect redis-service.qodiqa.svc.cluster.local:6380 \
  -cert /var/run/secrets/redis-tls/tls.crt \
  -key /var/run/secrets/redis-tls/tls.key \
  -CAfile /var/run/secrets/redis-tls/ca.crt \
  -verify 5 2>&1 | grep -E 'subject=|issuer=|notAfter='

# Verify the new certificate expiry date
openssl x509 -enddate -noout -in /tmp/redis-client-new.pem | cut -d= -f2
```

### 5.2 System Health After Rotation

```bash
# All health checks must pass after certificate rotation
curl -sf http://localhost:3000/health && echo "Liveness: OK"
curl -sf http://localhost:3000/ready && echo "Readiness: OK"

INTEGRITY=$(curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep qodiqa_execution_integrity_full | awk '{print $NF}')
[[ "$INTEGRITY" == "1" ]] && echo "Integrity: OK" || echo "CRITICAL: Integrity check failed"

# Run smoke tests
curl -fsS http://localhost:3000/health
```

---

## 6. Rollback Procedure

If certificate rotation causes connectivity failure:

```bash
# Rollback: restore previous certificates
CERT_BACKUP_DIR="/opt/qodiqa/backups/certs/certs-YYYYMMDD-HHMMSS"

# Restore Redis client cert
kubectl create secret generic redis-client-tls \
  --from-file=tls.crt="$CERT_BACKUP_DIR/redis-client.crt" \
  --from-file=tls.key="$CERT_BACKUP_DIR/redis-client.key" \
  --from-file=ca.crt="$CERT_BACKUP_DIR/redis-ca.crt" \
  -n qodiqa \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart QODIQA with old cert
kubectl rollout restart deployment/qodiqa -n qodiqa
kubectl rollout status deployment/qodiqa -n qodiqa --timeout=120s

# Verify recovery
curl -sf http://localhost:3000/ready && echo "Recovered with previous certificate"
```

---

## 7. Emergency Certificate Replacement

Emergency replacement is required when a certificate has expired or has ≤ 72 hours remaining with no renewal in progress.

### 7.1 Emergency Redis mTLS Certificate (Zero-Downtime)

```bash
# Step 1: Generate emergency certificate immediately
cat > /tmp/emergency-redis-csr.json << EOF
{
  "CN": "qodiqa-redis-emergency-$(date +%Y%m%d%H%M%S)",
  "key": {"algo": "ecdsa", "size": 256},
  "names": [{"O": "QODIQA Platform", "OU": "Emergency"}]
}
EOF

cfssl gencert \
  -ca="$REDIS_TLS_CA_KEY_CERT" \
  -ca-key="$REDIS_TLS_CA_KEY" \
  -config="${CERT_DIR}/ca-config.json" \
  -profile=client \
  /tmp/emergency-redis-csr.json | cfssljson -bare /tmp/redis-emergency

# Step 2: Verify the emergency certificate
openssl x509 -text -noout -in /tmp/redis-emergency.pem | grep -E 'Not Before:|Not After:'

# Step 3: Deploy immediately
kubectl create secret generic redis-client-tls \
  --from-file=tls.crt=/tmp/redis-emergency.pem \
  --from-file=tls.key=/tmp/redis-emergency-key.pem \
  --from-file=ca.crt="$REDIS_TLS_CA" \
  -n qodiqa \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/qodiqa -n qodiqa
kubectl rollout status deployment/qodiqa -n qodiqa --timeout=120s

# Step 4: Verify recovery
curl -sf http://localhost:3000/ready && echo "Emergency certificate deployed successfully"

# Step 5: Schedule proper certificate renewal within 48 hours
echo "REMINDER: Replace emergency certificate with properly-managed certificate within 48 hours"
```

### 7.2 If Redis Certificate Has Already Expired

QODIQA will fail-closed with all enforcement blocked. Redis stores are disconnected.

```bash
# Symptoms:
curl -sf http://localhost:3000/ready
# Expected: 503

curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep redis_store_up
# Expected: all values = 0

# Action: Deploy emergency certificate (above), then restart QODIQA
# QODIQA reconnects to Redis on startup and enforcement resumes
```

---

## 8. Validation Checklist

```
CERTIFICATE EXPIRATION/ROTATION CHECKLIST — QODIQA
Date: __________  Operator: __________

MONITORING
[ ] Daily certificate expiry check configured and running
[ ] Prometheus alerts configured (30-day warning, 14-day critical)
[ ] cert-manager configured for automatic renewal (if using K8s)
[ ] On-call runbook for certificate alerts updated

PLANNED RENEWAL (T-30 to T-14)
[ ] Certificate expiry dates reviewed: Redis: _____ PG: _____
[ ] New certificates generated
[ ] New certificates validated:
    [ ] Subject name: correct
    [ ] Expiry date: > 365 days
    [ ] CA signature: valid
    [ ] Key usage: client auth
[ ] Certificate tested in staging: PASS
[ ] Certificate backup taken: __________

ROTATION (T-14 or sooner)
[ ] Certificate backup of current certs: __________
[ ] Kubernetes Secret updated with new cert
[ ] QODIQA rolling restart initiated: __________
[ ] Rollout completed: __________

POST-ROTATION VERIFICATION
[ ] Redis PING with new cert: PONG
[ ] /health → 200: confirmed
[ ] /ready → 200: confirmed
[ ] qodiqa_execution_integrity_full{} = 1: confirmed
[ ] All redis_store_up metrics = 1: confirmed
[ ] Smoke tests 1-8: all PASS
[ ] New cert expiry confirmed: __________
[ ] Old cert retained in backup (not in use)

EMERGENCY (if applicable)
[ ] Reason for emergency: __________
[ ] Emergency cert duration: __________
[ ] Proper cert scheduled for replacement: __________

SIGN-OFF
Operator: __________  Time: __________
Secondary reviewer: __________
```

---

*Cross-references: [Key Compromise Runbook](key-compromise-runbook.md) | [Redis Failure Runbook](redis-failure.md) | [Disaster Recovery](disaster-recovery.md) | [Redis TLS Guide](../deployment/redis-tls.md)*
