# Filesystem Permissions

This document defines ownership, permission, and mount requirements for all
security-sensitive files and directories in a QODIQA production deployment.
Follow the principle of least privilege: every process and user account receives
only the permissions required for its specific function.

---

## Asset inventory

| Asset | Default path | Sensitivity | Required access |
|---|---|---|---|
| Encrypted key store | `data/keys.json` | Critical | qodiqa: rw, others: none |
| Audit log | `audit.log` | High | qodiqa: rw, others: none |
| Audit WAL | `audit.log.wal` | High | qodiqa: rw, others: none |
| Audit checksum | `audit.log.sum` | High | qodiqa: rw, others: none |
| Policy file | `policies.json` | Medium | qodiqa: r, others: none |
| Redis TLS CA cert | `REDIS_TLS_CA` path | Medium | qodiqa: r, others: none |
| Redis TLS client cert | `REDIS_TLS_CERT` path | Medium | qodiqa: r, others: none |
| Redis TLS client key | `REDIS_TLS_KEY` path | Critical | qodiqa: r, others: none |
| `.env` file | project root | Critical | root/deploy: r, others: none |
| Runtime logs (stdout/stderr) | collected by log driver | Low | process output only |

---

## Service account

Run QODIQA as a dedicated non-root service account.  Never run as `root` or as
a shared application account.

```bash
# Create a dedicated service account with no login shell and no home directory.
useradd --system --no-create-home --shell /usr/sbin/nologin qodiqa

# If a data directory is needed on the host:
mkdir -p /opt/qodiqa/data /opt/qodiqa/logs
chown -R qodiqa:qodiqa /opt/qodiqa/data /opt/qodiqa/logs
```

The service account requires:
- No sudo access
- No login shell
- No membership in privileged groups (`docker`, `sudo`, `wheel`, `adm`)
- No writable access outside `/opt/qodiqa/data` and `/opt/qodiqa/logs`

---

## Key store (`data/keys.json`)

The key store contains AES-256-GCM encrypted Ed25519 private key material.
The encryption key (KEK) lives in `QODIQA_KEY_ENCRYPTION_KEY` and must never be
stored on disk.

```bash
# Set ownership exclusively to the service account
chown qodiqa:qodiqa /opt/qodiqa/data/keys.json

# Owner read/write only — no group, no world access
chmod 600 /opt/qodiqa/data/keys.json

# Protect the parent directory — no traversal for others
chmod 700 /opt/qodiqa/data
chown qodiqa:qodiqa /opt/qodiqa/data
```

The `data/` directory should be on a persistent volume.  No other process
should have write access to it.  In environments where the data directory is
mounted from a secret store or encrypted volume, ensure the mount is not
world-readable.

### Atomic write protection

The key store writer creates a `.tmp` file in the same directory before
renaming it into place.  Ensure the directory is writable by `qodiqa` but not
by any other user or group.

---

## Audit log (`audit.log`, `.wal`, `.sum`)

The audit log is a cryptographically chained append-only file.  Write access
must be restricted to the QODIQA process.  Any other writer can forge or
truncate entries.

```bash
# Create the audit log directory
mkdir -p /opt/qodiqa/logs
chown qodiqa:qodiqa /opt/qodiqa/logs
chmod 700 /opt/qodiqa/logs

# After first run, lock down the log files
chown qodiqa:qodiqa /opt/qodiqa/logs/audit.log
chown qodiqa:qodiqa /opt/qodiqa/logs/audit.log.wal
chown qodiqa:qodiqa /opt/qodiqa/logs/audit.log.sum
chmod 600 /opt/qodiqa/logs/audit.log
chmod 600 /opt/qodiqa/logs/audit.log.wal
chmod 600 /opt/qodiqa/logs/audit.log.sum
```

**Do not mount the audit log directory as a shared volume** with other services.
If you need to ship audit log contents to a SIEM, use a read-only sidecar
container or a dedicated log shipping agent that has read-only access.

### Log shipping agent permissions

```bash
# If a log shipper (e.g. Fluentd, Filebeat) reads the audit log:
# Add the shipper user to a dedicated group, not to the qodiqa group.
groupadd auditreaders
usermod -aG auditreaders fluentd

# Change group ownership of the log directory
chown qodiqa:auditreaders /opt/qodiqa/logs
chmod 750 /opt/qodiqa/logs
chmod 640 /opt/qodiqa/logs/audit.log
```

---

## Policy file (`policies.json`)

The policy file controls enforcement behavior.  It must be readable by QODIQA
but should not be writable at runtime. the file is import-only: it seeds an empty control-plane store once, and later edits change nothing (SIGHUP re-reads the control plane, not this file — `src/core/policy/store.js` header). Change policy through the policy API.

```bash
chown root:qodiqa /opt/qodiqa/config/policies.json
chmod 640 /opt/qodiqa/config/policies.json

# The config directory should not be writable by qodiqa
chmod 750 /opt/qodiqa/config
chown root:qodiqa /opt/qodiqa/config
```

In Kubernetes, mount the policy file from a `ConfigMap` with `readOnly: true`.

---

## Redis TLS certificates

### CA certificate

```bash
chown root:qodiqa /etc/qodiqa-tls/ca.crt
chmod 640 /etc/qodiqa-tls/ca.crt
```

### Client certificate (mTLS)

```bash
chown root:qodiqa /etc/qodiqa-tls/client.crt
chmod 640 /etc/qodiqa-tls/client.crt
```

### Client private key (mTLS) — most sensitive

```bash
# Owner read only — absolutely no group or world access for private keys.
chown root:qodiqa /etc/qodiqa-tls/client.key
chmod 440 /etc/qodiqa-tls/client.key
```

Some deployments use `400` (owner read only) for the private key.
Either `440` (owner + group read) or `400` (owner only) is acceptable.
`440` is appropriate when the service account is the owning group.
Never use `644` or higher for a private key file.

```bash
# Protect the TLS directory itself
chmod 750 /etc/qodiqa-tls
chown root:qodiqa /etc/qodiqa-tls
```

---

## Environment file (`.env`)

The `.env` file contains secrets: `QODIQA_KEY_ENCRYPTION_KEY`,
`QODIQA_EXECUTION_INVARIANT_SECRET`, `OPENAI_API_KEY`, and optionally `REDIS_PASSWORD`.
There is no `QODIQA_SIGN_TOKEN` — `POST /sign` authenticates callers via individually-issued
signing identities (`data/signing-identities.json`, not an env var; see
`docs/configuration/reference.md`), which is out of scope for this document since it
governs `.env`/env-var permissions specifically.
It must never be world-readable.

```bash
chown root:qodiqa .env
chmod 640 .env
```

In production, prefer injecting secrets via a secret management system
(AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets) rather than a
plain `.env` file on disk.  The `.env` file is acceptable for development only.

### Gitignore verification

Confirm `.env` is excluded from version control:

```bash
grep -n '\.env' .gitignore
# Expected: at least one entry matching .env
```

---

## Persistent volume layout

Recommended directory structure for a production host or container volume:

```
/opt/qodiqa/
├── config/          750 root:qodiqa    — policy files, read-only at runtime
│   └── policies.json  640 root:qodiqa
├── data/            700 qodiqa:qodiqa  — key store, read-write
│   ├── keys.json    600 qodiqa:qodiqa
│   └── keys.json.tmp (transient, same permissions as keys.json)
└── logs/            700 qodiqa:qodiqa  — audit log, read-write
    ├── audit.log    600 qodiqa:qodiqa
    ├── audit.log.wal  600 qodiqa:qodiqa
    └── audit.log.sum  600 qodiqa:qodiqa

/etc/qodiqa-tls/     750 root:qodiqa   — TLS certificates, read-only
├── ca.crt           640 root:qodiqa
├── client.crt       640 root:qodiqa
└── client.key       440 root:qodiqa   — most sensitive
```

---

## Kubernetes volume permissions

### Key store — PersistentVolumeClaim

```yaml
volumes:
  - name: keystore
    persistentVolumeClaim:
      claimName: qodiqa-keystore

volumeMounts:
  - name: keystore
    mountPath: /opt/qodiqa/data
    readOnly: false          # qodiqa must write during key rotation

# Ensure the pod securityContext sets fsGroup so the PVC is group-owned
# by qodiqa's GID, not root.
securityContext:
  runAsUser:  1000           # qodiqa UID
  runAsGroup: 1000
  fsGroup:    1000           # applied to all volume mounts
  runAsNonRoot: true
```

### Audit log — PersistentVolumeClaim

```yaml
volumes:
  - name: auditlog
    persistentVolumeClaim:
      claimName: qodiqa-auditlog

volumeMounts:
  - name: auditlog
    mountPath: /opt/qodiqa/logs
    readOnly: false          # audit log is append-only but must be writable
```

### TLS certificates — Secret

```yaml
volumes:
  - name: redis-tls
    secret:
      secretName: qodiqa-redis-tls
      defaultMode: 0440      # owner + group read only for all files
      items:
        - key: ca.crt
          path: ca.crt
          mode: 0440
        - key: client.crt
          path: client.crt
          mode: 0440
        - key: client.key
          path: client.key
          mode: 0400         # private key: owner read only

volumeMounts:
  - name: redis-tls
    mountPath: /etc/qodiqa-tls
    readOnly: true
```

### Policy file — ConfigMap

```yaml
volumes:
  - name: policies
    configMap:
      name: qodiqa-policies
      defaultMode: 0440

volumeMounts:
  - name: policies
    mountPath: /opt/qodiqa/config/policies.json
    subPath: policies.json
    readOnly: true
```

### Application secrets — Kubernetes Secret

```yaml
volumes:
  - name: app-secrets
    secret:
      secretName: qodiqa-secrets
      defaultMode: 0400

volumeMounts:
  - name: app-secrets
    mountPath: /run/secrets/qodiqa
    readOnly: true
```

Reference the mounted secrets in environment variables:

```yaml
env:
  - name: QODIQA_KEY_ENCRYPTION_KEY
    valueFrom:
      secretKeyRef:
        name: qodiqa-secrets
        key: key-encryption-key
  - name: QODIQA_EXECUTION_INVARIANT_SECRET
    valueFrom:
      secretKeyRef:
        name: qodiqa-secrets
        key: execution-invariant-secret
```

---

## Container filesystem recommendations

### Read-only root filesystem

Mount the root filesystem read-only and provide writable `emptyDir` volumes for
only the directories that must be writable at runtime:

```yaml
securityContext:
  readOnlyRootFilesystem: true

volumeMounts:
  # Writable at runtime — key store and audit log use PVCs (see above)
  # Writable at runtime — Node.js needs a writable /tmp
  - name: tmp
    mountPath: /tmp

volumes:
  - name: tmp
    emptyDir: {}
```

With a read-only root filesystem, an attacker who achieves code execution cannot
write new binaries, modify startup scripts, or install persistence mechanisms.

### No world-writable directories

Verify no world-writable directories exist in your container image:

```bash
docker run --rm qodiqa:latest find / -xdev -perm -o+w -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null
# Expected output: only /tmp (or nothing)
```

### No SUID/SGID binaries

```bash
docker run --rm qodiqa:latest find / -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null
# Expected output: empty (no SUID/SGID binaries needed)
```

---

## Permission verification script

Use this script to verify permissions on a running host before go-live:

```bash
#!/usr/bin/env bash
set -euo pipefail

ERRORS=0

check() {
  local path="$1" expected_mode="$2" expected_owner="$3"
  if [ ! -e "$path" ]; then
    echo "MISSING: $path"
    ERRORS=$((ERRORS + 1))
    return
  fi
  local mode owner
  mode=$(stat -c '%a' "$path")
  owner=$(stat -c '%U:%G' "$path")
  if [ "$mode" != "$expected_mode" ]; then
    echo "WRONG MODE: $path — got $mode, want $expected_mode"
    ERRORS=$((ERRORS + 1))
  fi
  if [ "$owner" != "$expected_owner" ]; then
    echo "WRONG OWNER: $path — got $owner, want $expected_owner"
    ERRORS=$((ERRORS + 1))
  fi
}

check /opt/qodiqa/data              700 qodiqa:qodiqa
check /opt/qodiqa/data/keys.json    600 qodiqa:qodiqa
check /opt/qodiqa/logs              700 qodiqa:qodiqa
check /opt/qodiqa/config            750 root:qodiqa
check /opt/qodiqa/config/policies.json 640 root:qodiqa
check /etc/qodiqa-tls               750 root:qodiqa
check /etc/qodiqa-tls/ca.crt       640 root:qodiqa
check /etc/qodiqa-tls/client.crt   640 root:qodiqa
check /etc/qodiqa-tls/client.key   440 root:qodiqa

if [ "$ERRORS" -gt 0 ]; then
  echo "FAILED: $ERRORS permission check(s) failed"
  exit 1
fi
echo "OK: all permission checks passed"
```
