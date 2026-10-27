# Encryption at rest

Two layers, with different jobs. Neither replaces the other.

## 1. Application-level (QODIQA does this)

Sensitive values that are **not** part of a hash chain are encrypted by the application before they are written, with AES-256-GCM, under keys that come from the
platform's Key Encryption Key (KEK) provider (`QODIQA_KMS_PROVIDER`: local env, Vault, AWS/Azure/GCP KMS, HSM).

| Data | Where | Mechanism |
|---|---|---|
| Signing, transparency and checkpoint private keys | key files / stores | KEK envelope (`services/artifact/keyEncryption.js`); dedicated KEKs for transparency and checkpoint are optional |
| Webhook signing secrets | `webhook_endpoints.secret_enc` | KEK, `webhookSecrets.js` |
| MFA (TOTP) secrets | RBAC store | KEK, `mfa.js` |
| **Arguments of an approval request** | `approval_requests.args` | `src/infra/crypto/fieldEncryption.js`: `{"$qfe":"qfe1.<kid>.<iv>.<ciphertext>.<tag>"}` |

**Field encryption.** The key is `HKDF-SHA256(KEK, "QODIQA::FIELD::V1", purpose)`, so a value sealed for one purpose cannot be opened as another. The authenticated data
binds the ciphertext to its tenant, table, row and column, so a sealed value copied into another row fails to open. A dedicated KEK for fields can be set with
`QODIQA_FIELD_KEY_ENCRYPTION_KEY` (64 hex characters); unset, the shared KEK is used. `kid` (4 bytes of the KEK's SHA-256) names the key that sealed a value, so a rotated key is
reported as `FIELD_KEY_MISMATCH` and not as corruption. Modes (`QODIQA_FIELD_ENCRYPTION`): `auto` (default; seals when a KEK is available, outside production stores plaintext with a
warning when it is not), `required` (refuses to store an unsealed value), `off`. **In production the mode is `required`.** Rows written before encryption was enabled are still read as
they are, so enabling it needs no data migration.

**What is deliberately not encrypted at the application level.** The audit chain, the transparency log, action executions and approval *decisions* (hashes, ids, timestamps) are
hash-chained and meant to be verified by third parties; they carry no prompt or answer text (only hashes). Encrypting them would break verification without protecting anything
a hash does not already hide. Identifiers (tenant, agent, session ids) and the public parts of tools and MCP servers are not secrets.

**Honest limits of the current implementation.**

* Rotation. The KEK provider holds one KEK at a time. After a rotation, values sealed under the old key report `FIELD_KEY_MISMATCH`: the approval store then returns the request with
  `args: null, argsUnreadable` and **refuses to approve it** (an approver must see exactly what is approved). Approval requests are short-lived (pending requests expire after
  `QODIQA_APPROVAL_TTL_SECONDS`, 10 minutes by default), so the practical procedure is to rotate when none is open. `reseal()` exists for a bulk migration; there is no bulk tool
  yet. Closed requests keep their sealed arguments and become unreadable after a rotation; their hashes and decisions are unaffected.
* The application sees plaintext in memory while it works. Field encryption protects the database, backups and replicas, not a compromised process.
* It does not hide *that* a row exists, its size, or its timestamps.

## 2. Infrastructure-level (the operator does this)

Application-level encryption does not cover the rest of what a database and its host hold. Recommended:

* **PostgreSQL data directory and WAL:** encrypt the volume (LUKS/dm-crypt, BitLocker, or the cloud provider's managed disk encryption with a customer-managed key). PostgreSQL has no
  built-in TDE; a managed service's storage encryption is the equivalent. Keep the keys in the same KMS as the KEK, under separate key ids and separate access policy.
* **Backups and DR archives:** encrypt them with a key that is **not** stored with them; restore drills (`scripts/dr/`) must include the key retrieval step.
* **Redis:** TLS in transit (the production compose already requires it); the persistence volume is encrypted like the database volume. Redis holds short-lived state (nonces, rate
  counters, caches), not long-term records.
* **Logs and the SIEM stream:** the log sanitiser removes secrets and personal values before a line is written; the destination (file, shipper, SIEM) still needs encryption at rest.
* **Transit:** TLS everywhere (clients to the gateway, gateway to PostgreSQL and Redis, gateway to MCP servers with pinned keys).
* **Key separation:** KEKs, database credentials and backup keys belong to different owners where the organisation allows it.
