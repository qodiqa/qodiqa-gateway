# QODIQA Cryptography Guide

This document is the authoritative reference for every cryptographic primitive, protocol, and
design decision used in QODIQA. Read this document before integrating QODIQA or auditing its
security properties. Cross-references to the implementation are provided throughout.

**Related documents:**
- `docs/security/SECURITY_GUIDE.md` — security model and threat model
- — attack surface analysis
- `docs/security/key-management.md` — key lifecycle operations
- `docs/glossary.md` — term definitions

---

## 1. Algorithm Summary

| Purpose | Algorithm | Key size | Output size | Implementation |
|---------|-----------|----------|-------------|----------------|
| Artifact signing | Ed25519 | 32-byte private, 32-byte public | 64-byte signature | `src/infra/crypto/ed25519.js` |
| Key encryption at rest | AES-256-GCM | 32 bytes | variable + 16-byte tag | `services/artifact/keyEncryption.js` |
| All hashing | SHA-256 | — | 32 bytes | `src/infra/crypto/hashing.js` |
| Canonical serialization | fast-json-stable-stringify | — | variable | `src/utils/stableStringify.js` |
| Merkle tree (transparency) | SHA-256 with RFC 6962 prefixes | — | 32 bytes | `src/core/transparency/merkle.js` |
| Backup sealing | HMAC-SHA256 | variable | 32 bytes | `scripts/pg-backup.sh` |
| Nonce registration | Redis SET NX PX (no crypto) | — | — | `src/validation/nonceStore.js` |
| Timing-safe comparison | `crypto.timingSafeEqual` | — | boolean | multiple callers |

QODIQA does **not** use RSA, ECDSA, MD5, SHA-1, DES, 3DES, RC4, or any deprecated algorithm.

---

## 2. Ed25519 Signing

### 2.1 Algorithm

QODIQA uses Ed25519 (Edwards-curve Digital Signature Algorithm over Curve25519) as specified in
RFC 8032. Ed25519 was chosen for the following properties:

- **Deterministic**: identical inputs always produce identical signatures; no random number
  generator quality affects security.
- **Fast**: sign and verify are an order of magnitude faster than RSA-2048 at equivalent
  security level (~128-bit).
- **Small**: 32-byte public keys, 64-byte signatures.
- **No padding oracle**: unlike RSA-PKCS1, Ed25519 has no known padding oracle attacks.
- **Twist-attack resistant**: Curve25519 is specifically designed to be safe with standard
  implementations without constant-time code at the curve level.

### 2.2 Hash-then-Sign

QODIQA does **not** sign raw message bytes. Instead, it hashes the canonicalized artifact
payload first, then signs the hash:

```
hash   = SHA-256(DOMAIN_STRING || stableStringify(payload))
signature = Ed25519.sign(hash, privateKey)
```

This two-step pattern:
1. Produces a fixed-size input to the signing operation regardless of payload size.
2. Applies domain separation before hashing to prevent cross-protocol reuse.
3. Allows the same hash to be used for both signing and tamper detection.

### 2.3 Implementation

The signing implementation is in `src/infra/crypto/ed25519.js`:

```javascript
// sign(hashBuffer, privDer) → base64 signature string
// verify(hashBuffer, sig64B64, pubDer) → boolean (never throws)
```

Key encoding: DER-encoded PKCS#8 for private keys, DER-encoded SubjectPublicKeyInfo for public
keys. Node.js `crypto.sign` and `crypto.verify` are used directly (no third-party crypto library).

### 2.4 Signature Verification Guarantees

- `verify()` returns `false` on any error; it never throws.
- Verification uses `crypto.timingSafeEqual` internally on the signature bytes.
- A failed verification never leaks timing information about the expected signature.

---

## 3. AES-256-GCM Key Encryption

### 3.1 Key-Encryption-Key (KEK) Model

Ed25519 private keys are never stored in plaintext. Each private key is encrypted using
AES-256-GCM with a 256-bit KEK before being written to `data/keys.json`.

The KEK itself is stored outside the application:
- **Default (local)**: `QODIQA_KEY_ENCRYPTION_KEY` environment variable (64 hex chars = 32 bytes).
- **KMS-backed**: AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault, or PKCS#11 HSM. In
  KMS mode the KEK is a data encryption key generated and managed by the KMS; only the
  encrypted form (ciphertext) is stored locally. These providers are tested only against mocks and
  local emulators, never against a real cloud KMS or HSM — see the README's KMS table.

### 3.2 Encryption Parameters

```
IV:         12 bytes, cryptographically random (crypto.randomBytes(12))
Auth tag:   16 bytes (GCM default)
AAD:        key-store private keys: canonical record identity
            [label, trust domain, keyId, clientId, version, sha256(publicKeyDer)], blob carries
            aad: "qodiqa-keyrec-aad-v1". Blobs without the field (written before K1, and the MAC
            keyring / subject-pseudonym blobs) use no AAD and decrypt exactly as before.
Key size:   256 bits (32 bytes)
```

Encryption:
```
iv             = randomBytes(12)
{ ciphertext, authTag } = AES-256-GCM.encrypt(plaintext, KEK, iv)
stored = { iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'),
           authTag: authTag.toString('base64'), version: 1 }
```

Decryption:
```
plaintext = AES-256-GCM.decrypt(ciphertext, KEK, iv, authTag)
```

Authentication tag verification is performed by Node.js's GCM implementation before any
plaintext is released. A forged or tampered ciphertext will fail with an exception.

### 3.2a Authenticated key-store records

The public half of every key-store record (artifact `keys.json`, `transparency-keys.json`,
`checkpoint-keys.json`) is authenticated, so a writer of the file WITHOUT the KEK can no longer
inject or edit a record (for example a public-only 'deprecated' key with `retiredAt` ≈ now):

```
macKey     = HKDF-SHA256(KEK, salt = "", info = "qodiqa-keystore-record-mac-v1")   // 32 bytes
recordMac  = HMAC-SHA256(macKey, canonical JSON {label, trust domain, client bucket, map key,
             keyId, clientId, version, algorithm, purpose, publicKeyDer, status, createdAt,
             retiredAt, revokedAt, rotationDeadline, expiresAt, nativeKey, nativeRevocation,
             sha256(encrypted private-key blob), plaintext-present flag})
file       = { ..., recordSeal: { version: 1, mac: "HMAC-SHA256", aad: "qodiqa-keyrec-aad-v1", ... },
               <records each carrying recordMac> }
```

- A **sealed** file whose records do not all carry a valid MAC is refused (CRITICAL
  `KEY_RECORD_MAC_REFUSED` / `<STORE>_KEY_RECORD_MAC_REFUSED`): FATAL at boot, live store kept at reload.
- A **legacy** (unsealed) file is sealed once at bootstrap — trust on first use, WARN
  `KEY_RECORDS_SEALED`. Never at reload once the process has seen a sealed file;
  never when `QODIQA_KEYSTORE_REQUIRE_SEALED=true` (recommended in production after the first sealed boot).
- `validateKeyStore()` reports an unsealed or unauthentic file on disk as a violation (startup FATAL).
- The MAC needs the KEK. A verifier that holds only public keys (the independent offline verifier,
  `/.well-known` consumers) **cannot** check record MACs and must take its key set from an authenticated
  channel (the gateway's published keys), not from a copy of the key file.
- Implementation: `src/infra/crypto/keyRecordSeal.js` (pure), `deriveKekSubkey()` in `keyEncryption.js`.

### 3.3 Implementation

`services/artifact/keyEncryption.js`:
- `encryptKeyMaterial(privateKeyBuffer)` — returns `{ ciphertext, iv, authTag, version }`
- `decryptKeyMaterial(encryptedObj)` — returns plaintext `Buffer`
- (K1) `encryptKeyMaterial(buf, { aad, aadLabel })` / `decryptKeyMaterial(obj, { aad, aadLabel })` — AAD-bound
  variant; a blob carrying `aad` is refused without the matching AAD. `deriveKekSubkey(info)` — HKDF subkey.

The decryption function supports legacy field names for backwards compatibility during
migration. Version field is `1` for all keys encrypted by the current implementation.

### 3.4 KEK Security Properties

- The KEK **never** appears in log output. Application code never includes it in any
  value passed to `emit()`. As defense-in-depth, if a KEK value were ever passed under a
  recognized field name (e.g. `keyEncryptionKey`, `privateKey`), `services/logSanitizer.js`
  would redact it via field-name matching (the field's entire value is replaced with
  `[REDACTED]`) — there is no generic pattern that scans string values for arbitrary
  64-hex-character content.
- The KEK is wiped from process memory during graceful shutdown (step 15 of the shutdown
  sequence in `src/runtime/shutdown.js`).
- `src/infra/secrets/secretValidation.js` rejects a KEK that is all-zeros, has all nibbles
  equal, or consists of a repeating 2-character byte pattern (these indicate a low-entropy
  or placeholder value).
- Startup validation (`services/artifact/keyManager.js` `validateStartup()`) scans
  `data/keys.json` for any unencrypted private key material and aborts if found.

---

## 4. Hashing

### 4.1 SHA-256

All hash operations in QODIQA use SHA-256 (256-bit output). SHA-256 is used for:
- Artifact envelope hashing (before signing)
- Request binding hash
- Policy hash
- Audit chain hash (domain-separated hash of each entry's hash-protected core fields — 28 at the default schema v7, 38 at schema v8 when `QODIQA_AUDIT_SCHEMA_V8=true` — including `prevHash` — see §10)
- Transparency log entry hashing
- Evidence chain entry hashing
- Certificate artifact hashing
- Backup sealing (via HMAC-SHA256)

Implementation: `src/infra/crypto/hashing.js` wraps `crypto.createHash('sha256')`.
Convenience exports: `sha256Hex(buffer)`, `sha256Raw(buffer)`, `domainSeparatedHash(domain, data)`.

### 4.2 Domain-Separated Hashing

Every **protocol** hash in QODIQA (artifact envelope, request binding, policy, audit entry, evidence, transparency leaf/root, checkpoint) is domain-separated; a few internal digests are not (transparency `payloadHash`, `signatureRef`, evidence `canonicalHash`/`packageHash`/`bundleHash`, key fingerprints, artifact ids — correction; the earlier "every hash" wording was false). Domain separation prevents a hash value computed
in one context from being valid in another context. The domain string is prepended to the
hash input as a UTF-8 encoded prefix:

```
hash = SHA-256(Buffer.from(DOMAIN, 'utf8') || stableStringify(data))
```

Canonical domain strings (`ARTIFACT_DOMAINS`, `src/infra/crypto/hashing.js`; corrected 2026-10-02, the earlier table listed `ARTIFACT_DOMAINS.TRANSPARENCY` and `ARTIFACT_DOMAINS.NONCE`, which do not exist):

| Constant | Value |
|----------|-------|
| `ARTIFACT_DOMAINS.CANONICAL` | `QODIQA::CANONICAL::V1` |
| `ARTIFACT_DOMAINS.ARTIFACT` | `QODIQA::ARTIFACT::V1` |
| `ARTIFACT_DOMAINS.REQUEST` | `QODIQA::REQUEST::V1` |
| `ARTIFACT_DOMAINS.POLICY` | `QODIQA::POLICY::V1` |
| `ARTIFACT_DOMAINS.CERTIFICATE` | `QODIQA::CERTIFICATE::V1` |
| `ARTIFACT_DOMAINS.EVIDENCE` | `QODIQA::EVIDENCE::V1` |
| `ARTIFACT_DOMAINS.AUDIT` | `QODIQA::AUDIT::V1` |
| `ARTIFACT_DOMAINS.POLICY_GOVERNANCE` | `QODIQA::POLICY_GOVERNANCE::V1` |
| `ARTIFACT_DOMAINS.CONSENT` | `QODIQA::CONSENT::V1` |
| `ARTIFACT_DOMAINS.IDEMPOTENCY` | `QODIQA::IDEMPOTENCY::V1` |
| `ARTIFACT_DOMAINS.EXECUTION_INVARIANT` | `QODIQA::EXECUTION_INVARIANT::V1` (HMAC message domain) |
| `ARTIFACT_DOMAINS.BUNDLE` | `QODIQA::EVIDENCE_BUNDLE::V1` |

Tags defined outside `ARTIFACT_DOMAINS` (transparency `QODIQA::TRANSPARENCY::V1` / `QODIQA::TRANSPARENCY_ROOT::V1`, `QODIQA::POLICY::RULE::V1`, `QODIQA::AUDIT_CHECKPOINT::V1`, and others) are in the complete, generated registry — 33 tags, scanned from the source — in [`docs/protocol/QODIQA-PROTOCOL.md`](../protocol/QODIQA-PROTOCOL.md) §2; `npm run protocol:check` fails if that registry drifts from the code.

**Changing any domain string is a breaking change.** Doing so invalidates all existing
signatures, hashes, and proofs that used the old domain string.

---

## 5. Canonical JSON Serialization

### 5.1 Requirement

For a hash to be reproducible across environments, languages, and implementations, the
serialization of the input must be deterministic. JSON has no canonical form by default:
`{ "b": 1, "a": 2 }` and `{ "a": 2, "b": 1 }` are semantically equal but produce
different byte sequences.

### 5.2 Implementation

QODIQA implements `CanonicalSerialize(V)` (`docs/protocol/QODIQA-PROTOCOL.md`) in
`src/utils/stableStringify.js`, which wraps `fast-json-stable-stringify` for
key-sorting and leaf encoding, with an explicit normalization/validation pass
in front of it. It:
- Sorts object keys lexicographically (ascending UTF-16 code unit order) at all nesting levels.
- Produces no whitespace.
- Preserves array order.
- Maps `undefined` values to `null`, both in arrays and in objects.
- **Rejects** (throws `stableStringify.CanonicalizationError`, not a silent fallback):
  - `NaN` / `Infinity` / `-Infinity` numbers (spec §6.1: "if NaN or Infinity: ERROR").
  - Object own keys `"__proto__"`, `"constructor"`, or `"prototype"` (spec §6.1: "if any
    key is ... : ERROR") — this is a hard rejection, not a strip-and-continue, so a
    payload carrying one of these keys cannot be silently reduced to a form that
    collides with the untampered original.
  - Functions, symbols, and bigints (spec §6.1: "Unsupported value types ... MUST cause
    failure").
  - Any other non-plain-object value with no defined canonical form — `Date`, `RegExp`,
    `Error`, `Map`, `Set`, `ArrayBuffer`, `Buffer`/`TypedArray`, and class instances all
    have no own enumerable string keys reflecting their actual value, so admitting them
    would silently serialize every distinct instance to the same `"{}"` — a hash
    collision, not merely a lossy representation.
  - Circular references (explicit, deterministic rejection — never a native
    `RangeError`/stack overflow).
  - Nesting deeper than an internal `MAX_DEPTH` guard (deterministic rejection of
    pathological/attacker-supplied nesting, never a native stack overflow).

`src/validation/canonicalize.js`'s `hasUndefined()` check (which rejects `undefined`
before an artifact payload is even accepted, rather than letting it silently
canonicalize to `null`) is an additional, artifact-schema-specific layer on top of this —
not a workaround for a gap in stableStringify itself.

### 5.3 Interoperability

Third-party implementations must reproduce the same canonical form. The required behavior:
1. Sort all object keys lexicographically (UTF-16 code unit order).
2. No whitespace (no spaces, no newlines, no indentation).
3. Arrays in original order.
4. `undefined` serializes as `null`.
5. Numbers: standard JSON number format (no special float handling); `NaN`/`Infinity`/`-Infinity` MUST be rejected, not coerced.
6. Strings: standard JSON string escaping.
7. Object keys `"__proto__"`, `"constructor"`, `"prototype"` MUST be rejected outright.
8. Functions, symbols, and any value with no defined canonical JSON form (dates, maps, sets, binary buffers, etc.) MUST be rejected outright.

---

## 6. Artifact Envelope Hash

The artifact envelope hash is the value that Ed25519 signs. It is computed as:

```
envelopeHash = SHA-256(
  "QODIQA::ARTIFACT::V1"
  || stableStringify({ expiry, payload, publicKeyId, timestamp })
)
```

Where:
- `expiry` — Unix millisecond expiry timestamp
- `payload` — the full payload object (requestHash, policyHash, provider, etc.)
- `publicKeyId` — the key ID string
- `timestamp` — Unix millisecond signing timestamp

The four fields are sorted by key (lexicographic), so the canonical key order is always:
`expiry`, `payload`, `publicKeyId`, `timestamp`.

The signature is stored in the artifact as `signature` (base64, 64 bytes when decoded).

---

## 7. Request Binding Hash

The request binding hash cryptographically binds the artifact to a specific HTTP request:

```
requestHash = SHA-256(
  "QODIQA::REQUEST::V1"
  || stableStringify({ body, method, path })
)
```

Where:
- `method` — uppercase HTTP method string (`"POST"`)
- `path` — exact request path bytes, no normalization
- `body` — the complete parsed request body object

The hash is computed at signing time and embedded in `artifact.payload.requestHash`. At
enforcement time, QODIQA recomputes the hash from the incoming request and compares it
using `crypto.timingSafeEqual()`. A mismatch produces `REQUEST_MISMATCH`.

**Canonicalization rules for the request body:**
- Must be a plain object (no arrays at the top level).
- Must not contain `undefined` values at any depth.
- Must not exceed a configurable depth limit.

---

## 8. Policy Hash

The policy hash is an informational record of the policy set active at signing time:

```
policyHash = SHA-256("QODIQA::POLICY::V1" || stableStringify(policies))
```

(`_`-prefixed keys are stripped recursively before hashing.)

The policy hash is embedded in `artifact.payload.policyHash`. QODIQA compares this value
against the live policy hash at enforcement time and emits a `POLICY_DRIFT_DETECTED` warning
if they differ. Policy drift is **never** a block condition; it is forensic information only.

Implementation: `services/policyHash.js`.

---

## 9. Merkle Tree (Transparency Log)

### 9.1 RFC 6962 Construction

The transparency log uses a binary Merkle tree following RFC 6962. All hashes are SHA-256.
Two types of nodes:

```
Leaf node:     SHA-256(0x00 || entry_hash)
Internal node: SHA-256(0x01 || left_child_hash || right_child_hash)
```

The `0x00` / `0x01` prefixes prevent second-preimage attacks where a valid internal node
hash could be mistaken for a leaf node hash.

### 9.2 Root Computation

For a tree with `n` leaves, the root is computed bottom-up. If `n` is odd, the last leaf
is promoted unchanged. Implementation: `src/core/transparency/merkle.js`.

### 9.3 Inclusion Proof

An inclusion proof for leaf at index `i` in a tree of size `n` is the ordered list of
sibling hashes needed to reconstruct the root. The proof verifier:
1. Starts with `SHA-256(0x00 || entry_hash)`.
2. Iterates the proof path, applying `SHA-256(0x01 || left || right)` at each step.
3. Compares the reconstructed root against the stored root hash.

Returned by `GET /transparency/proof/:transparencyId`. Verifiable offline.

### 9.4 Consistency Proof

A consistency proof between root `m` (size `m`) and root `n` (size `n`, where `n > m`)
proves that the larger tree is a cryptographic extension of the smaller tree.
The proof has `O(log n)` elements. Implementation follows RFC 6962 section 2.1.2.

Returned by `GET /transparency/consistency/:fromRootId/:toRootId`. Verifiable offline.

---

## 10. Audit Chain Hash

> **correction:** the 9-field core below is audit **schema v1**. The default writer emits **schema v7** with 28 hash-protected fields (v2 +`publicKeyId`, `schemaVersion`; v3 +`consentProvenance`, `policyDecision`; v4 +`callerContext`; v5 +`provider`, `model`; v6 +`stage`, `reason`, `semantic`, `tokenUsage`, `responseId`; v7 +`entryType`, `outputHash`, `tenantId`, `requestId`, `organizationId`, `executionContext`, `executingProvider`). Schema v8 (38 fields, ten more) is written only when `QODIQA_AUDIT_SCHEMA_V8=true`; verifiers accept v1–v8. Normative contract: [`docs/protocol/QODIQA-PROTOCOL.md`](../protocol/QODIQA-PROTOCOL.md) §9 and.

Schema v1 — each audit entry's `hash` is a domain-separated SHA-256 over exactly 9 core fields
(`docs/protocol/QODIQA-PROTOCOL.md`):

```
coreFields = { artifactId, decision, inputHash, policyHash, prevHash,
               requestHash, signature, timestamp, verificationResult }
canonical  = CanonicalSerialize(coreFields)     -- sorted-key JSON, no whitespace
hash       = LowercaseHex(SHA-256(UTF8("QODIQA::AUDIT::V1") || canonical))
```

`prevHash` is one of the 9 hashed fields — it is the prior entry's `hash`, or the
literal string `"GENESIS"` for the first entry. Chain linkage and hash integrity
are therefore verified together in a single recomputation per entry.

Fields stored but intentionally excluded from the hash: `highResTime`
(a monotonic tiebreaker, not part of the cryptographic chain) and the OPTIONAL fields
`tenantId`, `organizationId`, `nonce`, `requestId`, `traceId`, `executionContext`. The current chain head hash
is maintained as `_tailHash`. Chain integrity can be verified offline by replaying the
NDJSON file and recomputing hashes (`src/core/audit/audit-log.js`).

---

## 11. Nonce Registration

Nonce registration is not a cryptographic operation. The `requestId` (UUID v4) is used
as a Redis key with `SET NX PX` (set-if-not-exists with TTL). The UUID itself is the
nonce; there is no additional hash or MAC.

The security property provided is uniqueness, not secrecy. An attacker who can observe
nonces in transit cannot forge them because nonces are validated only if they are present
in a valid, correctly signed artifact.

---

## 12. HMAC-SHA256 (Backup Sealing)

Backup files are sealed with `HMAC-SHA256(QODIQA_BACKUP_HMAC_KEY, backup_bytes)`. The
seal is stored alongside the backup and verified before any restore. This detects tampering
and accidental corruption of backup files. The HMAC key must be stored separately from the
backup files.

---

## 13. Timing-Safe Comparisons

All security-sensitive comparisons in QODIQA use `crypto.timingSafeEqual()`:

| Comparison | Location |
|------------|----------|
| Ed25519 signature verification | `src/infra/crypto/ed25519.js` |
| Request hash comparison | `src/validation/verifyRequestBinding.js` |
| Ops token comparison | `src/middleware/opsAuth.js` |
| Per-operator RBAC key comparison | `src/core/rbac/store.js` |
| Policy hash comparison | `services/policyHash.js` |

Using `===` for secret comparison enables timing attacks; `timingSafeEqual` runs in
constant time regardless of where the first differing byte occurs.

---

## 14. Cryptographic Assumptions

The security of QODIQA rests on the following cryptographic assumptions:

1. **Ed25519 hardness**: Discrete logarithm in the Ed25519 group is computationally
   infeasible for an adversary without the private key.

2. **SHA-256 collision resistance**: No practical collision exists for SHA-256. An adversary
   cannot construct two distinct payloads with the same SHA-256 hash.

3. **SHA-256 preimage resistance**: Given a SHA-256 hash, it is computationally infeasible
   to find any input that hashes to that value.

4. **AES-256-GCM security**: AES-256-GCM is IND-CCA2 secure under the assumption that AES
   is a pseudorandom permutation. The 12-byte nonce must be unique per (key, plaintext) pair.
   QODIQA generates nonces with `crypto.randomBytes(12)` which provides sufficient entropy.

5. **Node.js CSPRNG quality**: `crypto.randomBytes()` provides cryptographically secure
   random bytes. This is assumed to be seeded with sufficient entropy at startup.

6. **KEK secrecy**: The KEK must be kept secret. Compromise of the KEK allows decryption
   of all private key material in `keys.json`. Use a KMS-backed KEK in production for the
   highest assurance.

---

## 15. Algorithm Selection Rationale

### Why Ed25519 and not RSA or ECDSA?

- RSA-2048 and RSA-4096 require random padding (PKCS#1 v1.5 or OAEP). Padding oracle
  vulnerabilities have been found in RSA implementations repeatedly. Ed25519 has no padding.
- ECDSA requires a random nonce (k-value) per signature. A biased or repeated k-value
  leaks the private key (see Sony PS3 breach). Ed25519 is deterministic.
- Ed25519 is approximately 20x faster than RSA-2048 for signing and 5x faster for verification.
- Ed25519 keys are 32 bytes. RSA-2048 keys are 256 bytes.

### Why AES-256-GCM and not AES-128-CBC?

- GCM provides authenticated encryption: decryption fails if the ciphertext has been
  tampered with. CBC provides only confidentiality; a tampered CBC ciphertext may decrypt
  successfully to garbage, which could be exploited.
- AES-256 provides a 128-bit security margin (vs. AES-128 at 64-bit against Grover's
  algorithm in the quantum setting), matching the security level of Ed25519.

### Why SHA-256 and not SHA-3?

SHA-256 is the industry standard for this class of application. It is implemented in hardware
on modern CPUs (SHA-NI instruction set extension), providing better performance. SHA-3 is not
required by the current threat model but is not precluded for future versions.

### Why domain separation?

Without domain separation, a hash value computed for one purpose (e.g., a transparency log
entry) could potentially be valid in another context (e.g., an artifact payload). Domain
separation eliminates this class of cross-protocol attack by ensuring hash inputs in different
contexts are always distinguishable at the byte level, even if the data portions are identical.

---

## 16. Key Material Lifecycle

```
Generate Ed25519 keypair
  ↓
encrypt(privateKey, KEK) → store in keys.json
  ↓
Active (used for signing)
  ↓  [POST /key-admin/{clientId}/rotate-graceful — the default /rotate is emergency mode and revokes instead]
Deprecated (retained for verification only, no longer signs)
  ↓  [POST /key-admin/{clientId}/revoke]
Revoked (removed from active/deprecated sets; public key retained in archive)
```

Revoked keys are never selected for signing or verification by QODIQA. **Corrected 2026-10-02:** `src/validation/resolveKey.js` internally reports a missing, unknown or revoked `publicKeyId` as `KEY_NOT_FOUND`, but `validateArtifact` surfaces every unresolvable key as `INVALID_SIGNATURE` (no key-existence oracle), so `KEY_NOT_FOUND` never reaches the wire. A key that resolves is then subject to the lifecycle check after signature verification: revoked → `KEY_REVOKED`, archived → `KEY_ARCHIVED`, and a deprecated key verifies only artifacts signed before its retirement, within 65 s of it. The archive file
(`data/key-archive.json`) retains public key material for historical record.

**This guarantee is scoped to QODIQA itself.** For a native signing provider (Vault Transit
or an HSM/KMS), revocation additionally attempts to disable or destroy the key at the
provider, but that provider-side call can fail or be limited by what the provider supports —
QODIQA revoking a key does not, on its own, guarantee the external provider has stopped
honoring signing requests for it. See `docs/security/key-management.md`'s "External Key Providers (Vault
Transit / HSM / KMS)" section and finding for the full explanation and the
provider-specific steps operators must also take during a key-compromise response.

---

## 17. Implementation Files Reference

| Component | File |
|-----------|------|
| Ed25519 sign/verify | `src/infra/crypto/ed25519.js` |
| SHA-256 and domain-separated hash | `src/infra/crypto/hashing.js` |
| Canonical JSON | `src/utils/stableStringify.js` |
| Artifact canonicalization | `src/validation/canonicalize.js` |
| Envelope hash computation | `src/validation/canonicalize.js` `envelopeHash()` |
| Request hash computation | `src/validation/requestHash.js` |
| Policy hash | `services/policyHash.js` |
| AES-256-GCM key encryption | `services/artifact/keyEncryption.js` |
| Key store (key lifecycle) | `services/artifact/keyStore.js` |
| Key manager (API) | `services/artifact/keyManager.js` |
| Merkle tree | `src/core/transparency/merkle.js` |
| Transparency log | `src/core/transparency/log.js` |
| Transparency signer | `src/core/transparency/transparencySigner.js` |
| Nonce store | `src/validation/nonceStore.js` |
| Timing-safe utilities | `src/infra/crypto/hashing.js` `timingSafeCompare()` |
| Evidence package generation + offline verification | `src/core/evidence/generator.js` |
| Evidence package PDF export | `src/api/routes/evidence.js` |
| Standalone external evidence verifier (no QODIQA imports) | `tools/verify/verify.evidence.external.js` |

---

## 18. Evidence Package Export & Offline Verification

### 18.1 Problem this section documents

Prior to remediation, `GET /evidence/package/:artifactId[/json|/pdf]` exported a
`publicFingerprint` field truncated to the first 32 base64 characters of the
public key, and a `signatureField` truncated to the first 16 characters of the
signature, both suffixed with `…`. A partial signature or public key cannot be
base64/DER-decoded to a cryptographically meaningful value, so no external
party could independently verify an exported evidence bundle — the truncated
fields existed only as human-readable UI previews and were never fit for
export. This defeats QODIQA's evidence guarantee: *any evidence bundle can be
independently verified without trusting a running QODIQA instance.*

### 18.2 What every exported evidence package now contains

`generateEvidencePackage()` (`src/core/evidence/generator.js`) exports, in full
and never truncated:

| Field | Location in package | Purpose |
|-------|---------------------|---------|
| `signature` | `sections.artifact.signature`, `sections.verification.signature` | The full copy of the artifact's Ed25519 signature recorded at decision time |
| `publicKey` | `sections.key.publicKey`, `sections.verification.publicKey` | Full base64 SPKI/DER-encoded Ed25519 public key |
| `publicKeyId` | `sections.key.publicKeyId` | Key identifier used to attribute the signature |
| `algorithm` | `sections.key.algorithm`, `sections.verification.signatureAlgorithm` | Always `Ed25519` |
| `canonical` / `chainHashDomain` | `sections.artifact.canonical`, `sections.artifact.chainHashDomain` | Canonical JSON of the audit-chain entry's 9-11 hash-protected core fields (§10 above) and the domain string used to hash them — required to independently recompute `chainHash` |
| `chainHash` | `sections.artifact.chainHash` | The audit-chain entry's own SHA-256 domain-separated hash |

Any display-oriented shortening (e.g. a UI showing `default:key_v1…a1b2`) is a
presentation concern that must live in the frontend, never in exported JSON or
PDF evidence. The PDF export (`src/api/routes/evidence.js`) prints every one of
these fields in full — hash and signature rows are no longer passed through a
display-truncation helper.

### 18.3 The package-level Ed25519 seal

Every exported evidence package is *also* signed as a whole, not just quoting
copies of per-decision crypto material:

```
content   = { artifactId, generatedAt, artifact, policy, key, verification, audit }
canonical = CanonicalSerialize(content)
hash      = SHA-256(UTF8("QODIQA::EVIDENCE::V1") || canonical)
signature = Ed25519.sign(hash, activeSigningKey.privDer)
```

The signature, full public key, `keyId`, `signingAlgorithm`, `domain`, and
`signedAt` are exported under `package.integrity`. This is what lets a third
party trust that a QODIQA instance holding a specific key actually issued the
bundle — the pre-existing `packageHash` (plain SHA-256, `package.integrity.packageHash`)
only proved internal self-consistency, which anyone can forge by recomputing a
hash over arbitrary content. If no signing key is available (e.g. a
native-signing/HSM provider that only supports async signing), sealing degrades
to `signature: null` with `integrity.sealError` set — evidence viewing is never
blocked by a sealing failure, per this module's fail-safe (UNKNOWN, not ERROR)
contract.

### 18.4 Offline verification algorithm

An external verifier needs only the exported JSON and Node's built-in `crypto`
module — no QODIQA source, no database, no network call:

1. **Package hash** — recompute `SHA-256(CanonicalSerialize(content))` and
   compare to `integrity.packageHash`.
2. **Package seal** — recompute `SHA-256("QODIQA::EVIDENCE::V1" || canonical)`
   and verify it against `integrity.signature` using `integrity.publicKey`
   (Ed25519, per §2 above).
3. **Audit-chain entry hash** — recompute
   `SHA-256("QODIQA::AUDIT::V1" || sections.artifact.canonical)` and compare to
   `sections.artifact.chainHash` (§10 above), confirming the underlying
   decision record has not been altered since it was appended to the chain.

`verifyEvidencePackage()` in `src/core/evidence/generator.js` implements this
for internal use and tests. `tools/verify/verify.evidence.external.js` at the repository
root is a dependency-free, standalone re-implementation of the same three
checks intended to be copied out of this repository and run by an auditor,
regulator, or customer who does not have (and must not need) access to a
running QODIQA instance:

```
node tools/verify/verify.evidence.external.js evidence-package.json
```

### 18.5 Known limitation — decision-time artifact signature

The `signature` copied into `sections.artifact.signature` /
`sections.verification.signature` is the *original* artifact's Ed25519
signature, computed at decision time over
`SHA-256("QODIQA::ARTIFACT::V1" || CanonicalSerialize({expiry, payload,
publicKeyId, timestamp}))` (§6). QODIQA deliberately does not persist the full
`payload` or `expiry` in the audit chain (only hashes of request content, for
data-minimization reasons — see §10), so this specific signature is not
independently re-verifiable from the audit-chain record alone. It is exported
in full for forensic completeness and cross-referencing against the original
request, not as a self-contained proof. The package-level Ed25519 seal (§18.3)
and the audit-chain hash (§18.4 step 3) are what make the *exported evidence
package itself* independently and fully verifiable offline.

### 18.6 Evidence Bundle — adding transparency-log proof

The evidence package described above proves a decision is authentic and
unaltered, but not that it was ever entered into QODIQA's separate RFC6962
transparency log (§16-17) — that requires a Merkle inclusion proof, a
different artifact with its own offline verification primitives
(`src/core/transparency/merkle.js`). `GET /evidence/package/:artifactId/bundle`
combines both into one export — see `docs/security/evidence-bundle-verification.md`
for the full format and the standalone `tools/verify/verify.bundle.external.js` offline
verifier (same zero-dependency contract as §18.4's package verifier, plus
Merkle path reconstruction).

---

this document, the relevant implementation files, and `docs/glossary.md` in the same commit.*
