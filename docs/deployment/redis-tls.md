# Redis TLS and mTLS Deployment Guide

QODIQA uses Redis as the backbone for replay protection, anomaly detection, and
distributed rate limiting.  In production, all Redis traffic must travel over an
encrypted and authenticated channel.  This document covers TLS, mutual TLS
(mTLS), certificate validation requirements, Redis authentication practices, and
network isolation recommendations.

---

## Why encrypt Redis traffic

Redis stores security-critical state: nonce keys that guard replay protection,
anomaly counters, and rate-limit counters.  An attacker who can observe or
inject Redis traffic can:

* **Suppress replays** — delete nonce keys to re-open used request IDs.
* **Reset anomaly counters** — clear detection windows to hide abuse patterns.
* **Forge rate-limit state** — manipulate counters to bypass or trigger limits.

TLS prevents eavesdropping and injection on the network path between QODIQA and
Redis.  mTLS additionally prevents a rogue client from connecting to Redis even
if it has network access.

---

## Environment variables

| Variable | Purpose | Example |
|---|---|---|
| `REDIS_URL` | Connection string | `rediss://redis.internal:6380` |
| `REDIS_TLS` | Force TLS regardless of URL scheme | `true` |
| `REDIS_TLS_CA` | Path to PEM CA certificate | `/etc/redis-tls/ca.crt` |
| `REDIS_TLS_CERT` | Path to PEM client certificate (mTLS) | `/etc/redis-tls/client.crt` |
| `REDIS_TLS_KEY` | Path to PEM client private key (mTLS) | `/etc/redis-tls/client.key` |
| `REDIS_TLS_REJECT_UNAUTHORIZED` | `false` disables cert verification (unsafe) | `true` (default) |
| `REDIS_USERNAME` | Redis ACL username | `qodiqa` |
| `REDIS_PASSWORD` | Redis auth password | (strong random value) |

### URL scheme

Using `rediss://` in `REDIS_URL` enables TLS automatically:

```
REDIS_URL=rediss://redis.internal:6380
```

Alternatively, keep a plain `redis://` URL and set `REDIS_TLS=true`:

```
REDIS_URL=redis://redis.internal:6380
REDIS_TLS=true
```

Both forms are equivalent.  `rediss://` is preferred because it is
self-documenting and prevents accidental plain-text connections if `REDIS_TLS`
is later removed.

---

## TLS — server authentication only

Server-only TLS authenticates the Redis server to QODIQA.  The client presents
no certificate.  This is appropriate when Redis is inside a trusted VPC with
strict security groups and no mTLS infrastructure.

### Redis server configuration (`redis.conf`)

```
tls-port 6380
port 0

tls-cert-file  /etc/redis-tls/server.crt
tls-key-file   /etc/redis-tls/server.key
tls-ca-cert-file /etc/redis-tls/ca.crt

tls-auth-clients no
```

### QODIQA environment

```
REDIS_URL=rediss://redis.internal:6380
REDIS_TLS_CA=/etc/qodiqa-tls/ca.crt
REDIS_PASSWORD=<strong-random-password>
```

The CA certificate must be the issuer of the Redis server's certificate.  If
you use a public CA (e.g. Let's Encrypt), `REDIS_TLS_CA` is not needed because
the default system CA bundle is used.

---

## mTLS — mutual authentication

mTLS authenticates both sides of the connection: the Redis server presents a
server certificate, and QODIQA presents a client certificate.  Redis rejects
any client that does not present a certificate signed by the configured CA.

mTLS is the recommended transport for production deployments that require strong
connection-origin guarantees.

### Redis server configuration (`redis.conf`)

```
tls-port 6380
port 0

tls-cert-file    /etc/redis-tls/server.crt
tls-key-file     /etc/redis-tls/server.key
tls-ca-cert-file /etc/redis-tls/ca.crt

tls-auth-clients yes
```

`tls-auth-clients yes` requires every client to present a certificate signed by
the configured CA.  Unauthenticated clients are rejected at the TLS handshake.

### QODIQA environment

```
REDIS_URL=rediss://redis.internal:6380
REDIS_TLS_CA=/etc/qodiqa-tls/ca.crt
REDIS_TLS_CERT=/etc/qodiqa-tls/client.crt
REDIS_TLS_KEY=/etc/qodiqa-tls/client.key
REDIS_PASSWORD=<strong-random-password>
```

The client certificate and key must be:

* Signed by the same CA that Redis is configured to trust.
* Unique per QODIQA instance if you need per-pod revocability in Kubernetes.
* Stored with restricted permissions (`chmod 400` for the key file).

---

## Certificate validation requirements

| Requirement | Reasoning |
|---|---|
| `REDIS_TLS_REJECT_UNAUTHORIZED` must **not** be set to `false` in production | Disabling verification makes TLS trivially bypassable via MITM |
| CA certificate must be pinned via `REDIS_TLS_CA` or system trust store | Prevents accepting certificates from unexpected CAs |
| Server certificate CN or SAN must match the Redis hostname | Guards against certificate reuse across services |
| Client certificate (mTLS) key must be 2048-bit RSA or P-256+ ECDSA minimum | Ensures forward secrecy and acceptable key strength |
| Certificates must have explicit expiry dates | Prevents use of effectively-permanent certificates |

### `REDIS_TLS_REJECT_UNAUTHORIZED`

This variable exists to support development against local Redis with a
self-signed certificate where you control the CA.  Setting it to `false`
disables all certificate verification and must **never** be used in production.

QODIQA emits a startup warning whenever `REDIS_TLS_REJECT_UNAUTHORIZED=false`
is detected:

```json
{ "level": "WARN", "event": "REDIS_TLS_UNVERIFIED", ... }
```

Wire this event to your alerting system to detect accidental misconfiguration.

---

## Redis authentication

TLS secures the transport layer.  Redis ACL authentication secures the
application layer.  Both should be used together.

### Password authentication (Redis ≤ 5 / no ACLs)

```
# redis.conf
requirepass <strong-random-password>
```

```
# QODIQA env
REDIS_PASSWORD=<strong-random-password>
```

### ACL authentication (Redis ≥ 6)

Redis 6 ACLs provide per-user permissions.  Create a dedicated QODIQA user with
the minimum required permissions:

```
# redis.conf or ACL file
ACL SETUSER qodiqa on ><strong-random-password> ~qodiqa:* ~anomaly:* ~ratelimit:* +ping +set +get +del +exists +zadd +zremrangebyscore +zcard +incr +expire
```

```
# QODIQA env
REDIS_USERNAME=qodiqa
REDIS_PASSWORD=<strong-random-password>
```

Key prefixes used by QODIQA:

| Store | Key prefix |
|---|---|
| Nonce (replay protection) | `qodiqa:req:v2:` |
| Anomaly detection | `anomaly:v2:` |
| Rate limiting | `ratelimit:v1:` |

The ACL pattern `~qodiqa:* ~anomaly:* ~ratelimit:*` restricts the QODIQA user
to only these namespaces.

### Password strength requirements

Redis passwords are compared in constant time by the server but live in
environment variables on the application side.  Use a password of at least
32 random bytes (64 hex characters or a long random string).  Shorter passwords
are not sufficient.

---

## Network isolation recommendations

TLS and mTLS protect data in transit but do not replace network isolation.
Apply both:

### VPC / security group rules

* Redis must not be reachable from the public internet.
* Allow inbound to Redis port (default 6380 for TLS) only from QODIQA's
  security group or subnet CIDR.
* Deny all other inbound traffic to the Redis port.

### Kubernetes NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-ingress-qodiqa-only
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: redis
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: qodiqa
      ports:
        - protocol: TCP
          port: 6380
  policyTypes:
    - Ingress
```

This policy allows only pods labelled `app: qodiqa` to reach Redis on port 6380.
All other ingress is denied by default.

---

## Production deployment examples

### Docker Compose with TLS

```yaml
services:
  redis:
    image: redis:7-alpine
    command: >
      redis-server
        --tls-port 6380
        --port 0
        --tls-cert-file /etc/redis-tls/server.crt
        --tls-key-file  /etc/redis-tls/server.key
        --tls-ca-cert-file /etc/redis-tls/ca.crt
        --tls-auth-clients no
        --requirepass "${REDIS_PASSWORD}"
        --appendonly yes
        --appendfsync everysec
    volumes:
      - ./tls:/etc/redis-tls:ro
      - redis-data:/data
    networks:
      - backend

  qodiqa:
    image: qodiqa:latest
    environment:
      REDIS_URL: rediss://redis:6380
      REDIS_TLS_CA: /etc/qodiqa-tls/ca.crt
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
      STRICT_REPLAY_PROTECTION: "true"
    volumes:
      - ./tls:/etc/qodiqa-tls:ro
    networks:
      - backend
    depends_on:
      - redis

volumes:
  redis-data:

networks:
  backend:
    internal: true
```

### Docker Compose with mTLS

```yaml
services:
  redis:
    image: redis:7-alpine
    command: >
      redis-server
        --tls-port 6380
        --port 0
        --tls-cert-file /etc/redis-tls/server.crt
        --tls-key-file  /etc/redis-tls/server.key
        --tls-ca-cert-file /etc/redis-tls/ca.crt
        --tls-auth-clients yes
        --requirepass "${REDIS_PASSWORD}"
        --appendonly yes
        --appendfsync everysec
    volumes:
      - ./tls:/etc/redis-tls:ro
      - redis-data:/data
    networks:
      - backend

  qodiqa:
    image: qodiqa:latest
    environment:
      REDIS_URL: rediss://redis:6380
      REDIS_TLS_CA: /etc/qodiqa-tls/ca.crt
      REDIS_TLS_CERT: /etc/qodiqa-tls/client.crt
      REDIS_TLS_KEY: /etc/qodiqa-tls/client.key
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
      STRICT_REPLAY_PROTECTION: "true"
    volumes:
      - ./tls:/etc/qodiqa-tls:ro
    networks:
      - backend
    depends_on:
      - redis

volumes:
  redis-data:

networks:
  backend:
    internal: true
```

### Kubernetes with mTLS and cert-manager

```yaml
# Certificate for QODIQA client identity
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: qodiqa-redis-client
  namespace: production
spec:
  secretName: qodiqa-redis-client-tls
  issuerRef:
    name: redis-internal-ca
    kind: ClusterIssuer
  commonName: qodiqa-redis-client
  usages:
    - client auth

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qodiqa
  namespace: production
spec:
  template:
    spec:
      containers:
        - name: qodiqa
          env:
            - name: REDIS_URL
              value: "rediss://redis.production.svc.cluster.local:6380"
            - name: REDIS_TLS_CA
              value: /etc/redis-tls/ca.crt
            - name: REDIS_TLS_CERT
              value: /etc/redis-tls/tls.crt
            - name: REDIS_TLS_KEY
              value: /etc/redis-tls/tls.key
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: redis-credentials
                  key: password
            - name: STRICT_REPLAY_PROTECTION
              value: "true"
          volumeMounts:
            - name: redis-client-tls
              mountPath: /etc/redis-tls
              readOnly: true
      volumes:
        - name: redis-client-tls
          secret:
            secretName: qodiqa-redis-client-tls
            defaultMode: 0400
```

---

## Startup log events

QODIQA emits structured log events describing the Redis transport configuration
at startup.  These can be used for alerting and audit.

| Event | Level | Meaning |
|---|---|---|
| `REDIS_TLS_ENABLED` | INFO | TLS is active for this store |
| `REDIS_TLS_DISABLED` | INFO | TLS not configured (warn in production) |
| `REDIS_TLS_VALIDATED` | INFO | Probe succeeded over TLS connection |
| `REDIS_TLS_FAILED` | ERROR | TLS handshake or certificate error |
| `REDIS_AUTH_CONFIGURED` | INFO | Credentials are present |
| `REDIS_AUTH_MISSING` | WARN | No credentials configured |
| `REDIS_AUTH_VALIDATED` | INFO | Probe succeeded with configured credentials |
| `REDIS_AUTH_REJECTED` | ERROR | Server rejected credentials |
| `REDIS_TLS_UNVERIFIED` | WARN | `REDIS_TLS_REJECT_UNAUTHORIZED=false` detected |

Recommended alerts:

* `REDIS_TLS_FAILED` — immediate page; TLS handshake failure blocks all stores.
* `REDIS_AUTH_REJECTED` — immediate page; authentication failure blocks all stores.
* `REDIS_TLS_UNVERIFIED` — alert; cert verification is disabled.
* `REDIS_AUTH_MISSING` — alert; Redis is unauthenticated.
* `REDIS_TLS_DISABLED` — alert; traffic is unencrypted.

---

## Local development

Local development against a plain `redis://localhost:6379` (no TLS, no auth) is
supported and requires no additional configuration.  QODIQA emits `REDIS_TLS_DISABLED`
and `REDIS_AUTH_MISSING` warnings at startup, which are expected in this context.

Do not set `REDIS_TLS_REJECT_UNAUTHORIZED=false` in development unless you are
specifically testing TLS certificate handling.  If you need to test against a
local Redis with a self-signed cert, generate a local CA and pin it via
`REDIS_TLS_CA` instead.

---

## Certificate rotation

1. Issue a new server certificate from the same CA.
2. Update the Redis server certificate in-place (or restart Redis if hot-swap is
   not supported by your version).
3. Redis 7+ supports `CONFIG SET tls-cert-file` for zero-downtime rotation.
4. For mTLS: issue new client certificates, update the QODIQA secret/volume,
   and perform a rolling restart.
5. Only rotate CA certificates after all leaf certificates issued by the old CA
   have been replaced.  Changing the CA while leaf certificates are still in use
   will break all connections immediately.
