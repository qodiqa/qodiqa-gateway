# Production Deployment Checklist

Use this checklist to validate a QODIQA deployment before go-live or after a
significant infrastructure change.  Each item must be checked (✓) and the
result recorded.  The deployment is not ready for production until every item
in the **Critical** sections is satisfied.

**How to use this checklist:**
- Work through each section in order.
- Record pass/fail and the verifying operator for sign-off.
- For items marked **FAIL-SAFE**, failure means the deployment must not proceed.

---

## Section 1 — Startup Validation

> Verify by observing the startup log output.  All events listed below must
> appear at the `INFO` level.  Any `FATAL` event indicates a blocking issue.

### 1.1 Boot validation **[FAIL-SAFE]**

Since every environment and secret rule is enforced by one boot
validator before any listener opens (`src/infra/config/bootValidator.js`; the
full rule set with its production/development/test severities is
`docs/configuration/boot-rules.md`). A production process with any violation
exits non-zero with **one** `FATAL` `BOOT_VALIDATION_FATAL` event listing every
violation (`violations[].variable`, `.rule`, `.message`); it never starts
degraded. Replaces the earlier `ENV_VALIDATION_*` / `SECRET_VALIDATION_*` /
`NO_PROVIDER_CONFIGURED` / `KEY_ENCRYPTION_KEY_NOT_CONFIGURED` /
`CLIENT_ID_NOT_CONFIGURED` events.

- [ ] `BOOT_VALIDATION_OK` with `"profile":"prod"` — emitted at startup, no `BOOT_VALIDATION_FATAL`
- [ ] Every `BOOT_CONFIG_WARNING` has been read and is understood (in production
      the only expected one is the `QODIQA_KMS_PROVIDER` advisory when the
      local KMS provider is used)
- [ ] `NODE_ENV=production` is set explicitly (an unset or misspelled `NODE_ENV` refuses to boot)
- [ ] `QODIQA_KEY_ENCRYPTION_KEY` and `QODIQA_EXECUTION_INVARIANT_SECRET` are two different random 64-hex values
- [ ] At least one AI provider is enabled with a real, correctly-formatted credential
      (`PROVIDERS_CONFIGURED` lists it) — every provider key is checked for
      placeholders and format, not just `OPENAI_API_KEY`
- [ ] `QODIQA_DSR_PSEUDONYM_PEPPER` is set (≥ 32 random characters)
- The MAC keyring is provisioned once (`node scripts/security/macKeyring.js init`, same KEK as the nodes) and the same `mac-keys.json` is visible to every node at `QODIQA_MAC_KEYS_PATH` (default: beside `QODIQA_KEYS_PATH`) — `REVOCATION_SIGNING_KEY`/`ORG_STATUS_SIGNING_KEY` are no longer used
- [ ] `RL_ENABLED=true` and `REDIS_URL` use `rediss://` (or `REDIS_TLS=true`); PostgreSQL TLS is not disabled
- [ ] No semantic threshold, band, classifier or kill-switch override is set (all are refused in production)
- [ ] `QODIQA_ADMIN_ENABLED` / `QODIQA_DIAGNOSTICS_ENABLED` are set only if those planes are needed, and then `QODIQA_OPS_TOKEN` (≥ 32 characters) is set
- [ ] At least one signing identity is provisioned (there is no `QODIQA_SIGN_TOKEN` shared secret — see `docs/configuration/reference.md`)
- `node scripts/db/role-credentials.js --check` exits 0 on the target cluster.
- Witness key, trusted witness public keys and `QODIQA_ANCHOR_EXPORT_PATH` provisioned; the anchor export is copied to customer-held storage.
- `node src/infra/postgres/migrate.js --status` shows every migration of the chain applied.

### 1.2 Boot report

- [ ] `BOOT_REPORT` was emitted after `GATEWAY_START` (no `BOOT_REPORT_FAILED`)
- [ ] `report.postgres.tls.client.tls` is `true` and `report.postgres.tls.client.authorized` is `true`
- [ ] `report.postgres.migrations.pending` is `0`
- [ ] `report.redis.tlsEstablished` is `true`
- [ ] `report.rateLimit.protectionActive` is `true`
- [ ] `report.semantic.deviatesFromPinnedDefaults` is `false` and `report.semantic.fingerprint` matches the release's recorded value
- [ ] `report.planes` shows exactly the planes this deployment intends to expose

### 1.3 Key manager validation **[FAIL-SAFE]**

- [ ] `KEY_MANAGER_READY` — emitted at startup
- [ ] `activeKeys` count is ≥ 1
- [ ] `secretProvider` confirms the KEK source (`env:QODIQA_KEY_ENCRYPTION_KEY` or vault)
- [ ] `encryptionAlgorithm` is `aes-256-gcm`
- [ ] No `KEY_MANAGER_STARTUP_FAILED` event
- [ ] No `KEYSTORE_EMPTY` event

### 1.4 Policy validation **[FAIL-SAFE]**

- [ ] `POLICIES_LOADED` — emitted at startup
- [ ] Policy count is ≥ 1
- [ ] All expected policy IDs are present in the `ids` array
- [ ] No `POLICY_LOAD_FAILED` event

### 1.5 Redis store initialization

- [ ] `NONCE_STORE_READY` — emitted at startup
- [ ] `ANOMALY_STORE_READY` — emitted at startup (if anomaly store in use)
- [ ] `RATE_LIMIT_STORE_READY` — emitted at startup
- [ ] `GATEWAY_RUNTIME_READY` — emitted at startup (indicates all stores operational)
- [ ] `GATEWAY_STATE_READY` — emitted at startup
- [ ] `executionIntegrity: "FULL"` in `GATEWAY_START` event

### 1.6 Redis persistence validation

- [ ] `REDIS_PERSISTENCE_STATUS` — emitted with `safe: true`
- [ ] `REDIS_PERSISTENCE_VALIDATED` — emitted at startup
- [ ] `aofEnabled: true` in persistence status
- [ ] `appendfsync` is `everysec` or `always` in persistence status
- [ ] No `REDIS_PERSISTENCE_WARNING` events
- [ ] No `REDIS_PERSISTENCE_UNSAFE` event
- [ ] `STRICT_REPLAY_PROTECTION=true` is set in production environment

### 1.7 Redis security validation

- [ ] `REDIS_AUTH_CONFIGURED` — emitted at startup
- [ ] `REDIS_AUTH_VALIDATED` — emitted at startup (both store probes succeeded)
- [ ] `REDIS_TLS_ENABLED` — emitted at startup for each store
- [ ] `tlsVerified: true` in `REDIS_TLS_ENABLED` events
- [ ] No `REDIS_AUTH_MISSING` warning
- [ ] No `REDIS_TLS_DISABLED` event
- [ ] No `REDIS_TLS_FAILED` event

---

## Section 2 — Infrastructure Security

### 2.1 Network isolation **[FAIL-SAFE]**

- [ ] QODIQA port (3000) has no inbound rule from `0.0.0.0/0`
- [ ] Redis port (6380) is accessible only from QODIQA's security group/subnet
- [ ] Redis has no public IP address
- [ ] QODIQA has no public IP address (traffic routed via load balancer)
- [ ] Load balancer terminates TLS from clients (HTTPS only on public endpoint)
- [ ] Outbound egress from QODIQA restricted to: Redis (private), and only the hostname(s) of the enabled AI provider(s) — see `docs/deployment/cloud-deployment.md` for the full per-provider hostname table (e.g. `api.openai.com:443` for `openai`)

### 2.2 Redis security **[FAIL-SAFE]**

- [ ] Redis is not listening on a public interface
- [ ] Redis requires authentication (`requirepass` or ACL)
- [ ] Redis password is at least 32 random characters
- [ ] Redis TLS is enabled (`rediss://` or `REDIS_TLS=true`)
- [ ] TLS certificate verification is enabled (`REDIS_TLS_REJECT_UNAUTHORIZED` ≠ `false`)
- [ ] Redis ACL restricts the QODIQA user to the namespaces it uses
- [ ] Redis AOF persistence is enabled (`appendonly yes`)
- [ ] Redis `appendfsync` is `everysec` or `always`

### 2.3 TLS configuration

- [ ] Load balancer uses TLS 1.2 minimum (TLS 1.3 preferred)
- [ ] Load balancer cipher suite excludes known-weak ciphers (RC4, 3DES, NULL)
- [ ] Redis TLS certificate has a valid CN/SAN matching the Redis hostname
- [ ] Redis TLS CA certificate is pinned (not relying on public CA bundle for internal Redis)
- [ ] Redis client certificate (mTLS) is issued from the same CA as the Redis server cert
- [ ] TLS certificate expiry is monitored with an alert ≥ 30 days before expiry

### 2.4 Secret management **[FAIL-SAFE]**

- [ ] `QODIQA_KEY_ENCRYPTION_KEY` is stored in a secret management service (not in `.env` on disk)
- [ ] `QODIQA_EXECUTION_INVARIANT_SECRET` is stored in a secret management service
- [ ] The enabled AI provider credential(s) (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_API_KEY`, and/or `LOCAL_API_KEY`) are stored in a secret management service
- [ ] `REDIS_PASSWORD` is stored in a secret management service
- [ ] Secrets are not present in application logs, CI/CD pipeline output, or image layers
- [ ] Secret access is audited (all reads logged by the secret management service)
- [ ] Secret access policy uses least-privilege (QODIQA reads only its own secrets)
- [ ] `.env` file does not exist on the production server (or is `600 root:root`)
- [ ] Secrets are not committed to version control

### 2.5 Certificate management

- [ ] Certificate renewal is automated (ACM, cert-manager, or equivalent)
- [ ] Redis TLS certificates have an expiry date ≤ 1 year
- [ ] A runbook exists for emergency certificate rotation
- [ ] Certificate revocation procedure is documented

---

## Section 3 — Container Security

### 3.1 Non-root execution **[FAIL-SAFE]**

- [ ] Container runs as UID ≠ 0 (verify: `docker inspect --format '{{.Config.User}}' qodiqa:latest`)
- [ ] `runAsNonRoot: true` is set in the Kubernetes pod securityContext
- [ ] `runAsUser` is explicitly set to a non-zero UID (e.g. 1000)
- [ ] No `sudo` or `su` access exists within the container

### 3.2 Read-only filesystem **[FAIL-SAFE]**

- [ ] `readOnlyRootFilesystem: true` in Kubernetes container securityContext
- [ ] `--read-only` flag is set in Docker run
- [ ] Writable volumes are limited to: `/tmp`, key store mount, audit log mount
- [ ] No world-writable directories in the image (verify: `find / -xdev -perm -o+w`)
- [ ] No SUID/SGID binaries in the image (verify: `find / -xdev \( -perm -4000 -o -perm -2000 \)`)

### 3.3 Capability restrictions **[FAIL-SAFE]**

- [ ] `capabilities.drop: [ALL]` in Kubernetes container securityContext
- [ ] `--cap-drop ALL` in Docker run command
- [ ] No capabilities are added back (confirm `capabilities.add` is absent or empty)
- [ ] `allowPrivilegeEscalation: false` in Kubernetes container securityContext
- [ ] `--security-opt no-new-privileges:true` in Docker run

### 3.4 Resource limits

- [ ] CPU limit is set (Kubernetes `resources.limits.cpu`)
- [ ] Memory limit is set (Kubernetes `resources.limits.memory`)
- [ ] PID limit is set (`--pids-limit 128` in Docker, or equivalent)
- [ ] OOM behavior is tested — verify pod is restarted on OOM, not the node

### 3.5 Secret mounts

- [ ] Secrets are injected via `secretKeyRef` env vars or a mounted `Secret` volume
- [ ] Secret volumes are mounted with `readOnly: true`
- [ ] Secret volume `defaultMode` is `0400` (owner read only)
- [ ] Secrets are not passed as Docker build arguments
- [ ] Secrets are not present in `docker-compose.yml` committed to source control

### 3.6 Image security

- [ ] Image is based on a minimal base (Alpine, distroless, or equivalent)
- [ ] Image has been scanned with a vulnerability scanner (Trivy, Grype, or equivalent)
- [ ] No critical or high CVEs exist in the final image
- [ ] Image is signed (Cosign, Notary, or equivalent)
- [ ] Image digest is pinned in the deployment manifest (not a floating tag)
- [ ] Image does not contain `.env`, `*.pem`, `data/`, or `audit.log*` files
- [ ] `.dockerignore` excludes all sensitive files

---

## Section 4 — Filesystem Permissions

### 4.1 Key store

- [ ] `data/keys.json` is owned by the QODIQA service account
- [ ] `data/keys.json` permissions are `600` (owner read/write only)
- [ ] `data/` directory permissions are `700` (owner only)
- [ ] No other user or process has write access to the key store

### 4.2 Audit log

- [ ] `audit.log` is owned by the QODIQA service account
- [ ] `audit.log` permissions are `600`
- [ ] `audit.log.wal` and `audit.log.sum` are `600`
- [ ] The audit log directory is `700` (or `750` if a log shipper needs read access)

### 4.3 TLS certificates

- [ ] Redis TLS client private key is `440` or `400`
- [ ] Redis TLS certificates are `640` or `440`
- [ ] TLS directory is `750` (service account group-readable, not world-readable)

### 4.4 Configuration files

- [ ] `policies.json` is not writable by the QODIQA process at runtime
- [ ] Policy file permissions are `640` (root owner, qodiqa group-readable)

---

## Section 5 — Operations

### 5.1 Monitoring **[FAIL-SAFE]**

- [ ] Prometheus scrape is configured for the `/metrics` endpoint
- [ ] `redis_store_up` gauge is being collected for all three stores
- [ ] `execution_integrity_full` gauge is being collected
- [ ] Alerts are defined for `redis_store_up < 1` (any store, > 30s duration)
- [ ] Alerts are defined for `execution_integrity_full < 1` (> 60s duration)

### 5.2 Alerting **[FAIL-SAFE]**

- [ ] Alert exists for `FATAL` level log events
- [ ] Alert exists for `REDIS_AUTH_REJECTED` log event
- [ ] Alert exists for `REDIS_TLS_FAILED` log event
- [ ] Alert exists for `REPLAY_PROTECTION_DEGRADED` log event
- Alert exists for `BOOT_VALIDATION_FATAL` log event
- [ ] Alert exists for `GATEWAY_RUNTIME_DEGRADED` log event
- [ ] On-call rotation is defined and tested

### 5.3 Log retention

- [ ] Application log retention is ≥ 90 days
- [ ] Audit log (`audit.log`) is shipped to write-once storage (S3 Object Lock, GCS Retention Policy, etc.)
- [ ] Audit log retention is ≥ 1 year (or per your compliance requirement)
- [ ] Log storage is separate from the application host
- **audit retention prune is OFF by default** (`scripts/audit/prune.js`). It runs only when an operator runs it, with the server stopped (`--confirm-server-stopped`), and only after the owner sets a period (`QODIQA_AUDIT_RETENTION_DAYS`). Always run `--dry-run` first. It connects only with a dedicated identity in `QODIQA_PG_PRUNE_URL`, which must bypass RLS and hold DELETE on `audit_chain` / `evidence_chain_records` and INSERT on `audit_chain_prunes`. No running service is given these rights. Archives go to `--archive-root` (default `<audit.log dir>/audit-archive`) and must be shipped to the same write-once storage as `audit.log`. Transparency leaves are not pruned.

### 5.4 Backup

- [ ] `data/keys.json` is backed up to encrypted object storage
- [ ] Key store backup is tested — restore has been verified at least once
- Key store backup and KEK are held in **separate** custody (the KEK never sits with the encrypted key-store backup); both are restorable.
- [ ] Audit log backup is continuous (write-once streaming, not periodic snapshot)
- [ ] `policies.json` is in version control
- **backup role (migration 067).** Rotate `qodiqa_backup`'s placeholder password (`ALTER ROLE qodiqa_backup PASSWORD '<new>'`), and set it as secret `postgres-backup-password` (Kubernetes) or `PGPASSWORD` in `/etc/qodiqa/backup.env` (systemd). Never reuse the app role's password.
- **grant `pg_read_all_data` to the backup role, as the cluster superuser, once, at LIVE.** approved in principle 2026-09-30. Then regenerate with `member_of: ["pg_read_all_data"]` for `qodiqa_backup`, since PM-01 pins the role's memberships:
  ```sql
  GRANT pg_read_all_data TO qodiqa_backup;
  -- verify:
  SELECT pg_has_role('qodiqa_backup', 'pg_read_all_data', 'MEMBER');  -- must be true
  ```
- **Backups encrypted at rest:** `QODIQA_BACKUP_REQUIRE_ENCRYPTION=true`, distinct `backup-encryption-key` and `backup-hmac-key` (≥ 32 characters, ≠ KEK), and `pg-backup.sh verify` shows `BACKUP_SEAL_OK`/`BACKUP_VERIFY_OK`. Confirm whether the DR JSON path (`scripts/dr/postgres.js`) is encrypted before using it on LIVE. The backup role reads the control plane (privilege policy rule 7, accepted on the encryption condition).
- **`pg-backup.sh incremental` is UNSUPPORTED**. `pg_basebackup` needs the REPLICATION attribute, which is deliberately not granted to `qodiqa_backup`. The script refuses the command, and the `qodiqa-pg-backup-incremental` CronJob is suspended until a decision is made.

### 5.5 Recovery procedures

- [ ] Runbook exists for: Redis failure and recovery
- [ ] Runbook exists for: key store corruption or loss
- [ ] Runbook exists for: key encryption key (KEK) compromise
- [ ] Runbook exists for: execution invariant secret (`QODIQA_EXECUTION_INVARIANT_SECRET`) compromise
- [ ] Runbook exists for: signing identity compromise (revoke via `DELETE`-equivalent on `POST /signing-identities/:id/api-key`, or disable the identity)
- [ ] Runbook exists for: AI provider credential compromise (whichever of `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`GEMINI_API_KEY`/`MISTRAL_API_KEY`/`LLAMA_API_KEY`/`LOCAL_API_KEY` is in use)
- [ ] Runbook exists for: TLS certificate expiry or compromise
- [ ] Runbooks have been reviewed and tested in a staging environment

---

## Section 6 — Functional Verification

Run the following tests in the target environment (staging or production canary)
before full traffic promotion.

### 6.1 Artifact signing and verification

- [ ] `POST /sign` with a valid signing identity's `Authorization: Bearer sk_...` returns a signed artifact
- [ ] `POST /verify/v2` with the signed artifact returns `decision: ALLOW`
- [ ] `POST /verify/v2` with a tampered artifact body returns `decision: BLOCK`
- [ ] `POST /verify/v2` with a tampered signature returns `decision: BLOCK`
- [ ] `POST /sign` without a credential returns `401 UNAUTHORIZED`
- [ ] `POST /sign` with an unresolvable credential returns `401 UNAUTHORIZED`
- [ ] `POST /sign` with a disabled/revoked identity's credential returns `403 FORBIDDEN`

### 6.2 Replay protection **[FAIL-SAFE]**

- [ ] Re-submitting the same signed artifact to `/ai/chat` returns `decision: BLOCK`
  with reason `REPLAY_DETECTED`
- [ ] Re-submitting after the artifact TTL expires returns `decision: BLOCK`
  with reason `ARTIFACT_EXPIRED` (not REPLAY_DETECTED)
- [ ] Replay is blocked even when submitted from a different source IP

### 6.3 Policy enforcement

- [ ] A request matching a `BLOCK_IP` rule is blocked
- [ ] A request requiring consent without the consent header is blocked
- [ ] A request exceeding the rate limit is blocked
- [ ] A request outside the allowed time window is blocked (if a TIME_WINDOW policy is active)
- [ ] A fully valid request passes all checks and returns `decision: ALLOW`

### 6.4 Tamper rejection

- [ ] Modifying `artifact.payload.requestId` in a signed artifact causes `BLOCK`
- [ ] Modifying `artifact.payload.policyHash` causes `BLOCK`
- [ ] Modifying `artifact.signature` causes `BLOCK`
- [ ] Adding unexpected fields to the artifact header causes `BLOCK` or validation failure

### 6.5 Fail-closed behavior **[FAIL-SAFE]**

- [ ] When Redis is unreachable, `/ai/chat` returns `decision: BLOCK` (not `ALLOW`)
- [ ] `REPLAY_PROTECTION_DEGRADED` event is emitted when Redis is down
- [ ] When Redis reconnects, execution resumes without restart
- [ ] `GATEWAY_RUNTIME_RECOVERED` event is emitted after reconnect

### 6.6 Audit validation

- [ ] Every request to `/ai/chat` produces an entry in `audit.log`
- [ ] Audit chain (`audit.log.sum`) validates after a series of requests
- [ ] The audit log is not truncated or writable by non-qodiqa processes

---

## Section 7 — Key Management

- [ ] At least one active signing key exists (`activeKeys ≥ 1` in `GATEWAY_START`)
- [ ] Key rotation procedure has been tested in staging
- [ ] `KEY_ROTATION_SUCCESS` event is emitted after rotation
- [ ] `KEY_EXPIRY_WARNING` events are being monitored and alerted on
- [ ] Key rotation schedule is documented (recommended: 90 days)
- [ ] Deprecated keys are retained until all artifacts signed by them have expired
- [ ] Public key endpoint (`/public-key`, `/.well-known/jwks.json`) returns the active key

---

## Sign-off

| Section | Status | Verified by | Date |
|---|---|---|---|
| 1 — Startup Validation | | | |
| 2 — Infrastructure Security | | | |
| 3 — Container Security | | | |
| 4 — Filesystem Permissions | | | |
| 5 — Operations | | | |
| 6 — Functional Verification | | | |
| 7 — Key Management | | | |

**Deployment approved by:** _______________________

**Date:** _______________________

**Notes / exceptions:**

> Record any items that could not be completed, with justification and an
> accepted-risk date.  Items marked **[FAIL-SAFE]** must not be deferred without
> explicit sign-off from the security lead.
