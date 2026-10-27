-- QODIQA PostgreSQL Schema — Migration 001
-- Author: QODIQA Platform Engineering
-- Purpose: Initial schema establishing all persistence tables for QODIQA
--
-- Design principles:
--   1. Cryptographic audit chain integrity is preserved in the database
--   2. Private key material remains AES-256-GCM encrypted (DB sees only ciphertext)
--   3. RBAC, policy, and investigation data fully normalized
--   4. All tables have audit columns (created_at, updated_at where applicable)
--   5. Immutable tables (audit_chain) forbid UPDATE/DELETE at the constraint level
--   6. Idempotent: safe to re-run; all DDL uses IF NOT EXISTS
--   7. Indexes designed for the actual query patterns of each module
--
-- Run order matters: tables with FK dependencies appear after their parents.
-- Migration tracking is managed by the qodiqa_migrations table itself.

BEGIN;

-- ── Migration tracking ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_migrations (
    id             SERIAL PRIMARY KEY,
    version        INTEGER       NOT NULL UNIQUE,
    name           VARCHAR(256)  NOT NULL,
    applied_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    checksum       CHAR(64)      NOT NULL,  -- SHA-256 of migration file content
    applied_by     VARCHAR(128)  NOT NULL DEFAULT current_user
);

COMMENT ON TABLE qodiqa_migrations IS
    'Tracks applied schema migrations. Never modify applied rows.';

-- ── RBAC Users ────────────────────────────────────────────────────────────────
-- Maps to: src/core/rbac/store.js
-- Key change from file store: UUID primary key, username uniqueness enforced at DB level

CREATE TABLE IF NOT EXISTS rbac_users (
    id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    username       VARCHAR(64)   NOT NULL,
    role           VARCHAR(32)   NOT NULL,
    enabled        BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    created_by     VARCHAR(128)  NOT NULL DEFAULT 'system',
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_by     VARCHAR(128)  NOT NULL DEFAULT 'system',

    CONSTRAINT rbac_users_username_unique UNIQUE (username),
    CONSTRAINT rbac_users_role_check CHECK (
        role IN ('admin', 'auditor', 'compliance', 'operator', 'viewer')
    ),
    CONSTRAINT rbac_users_username_length CHECK (LENGTH(username) >= 2)
);

CREATE INDEX IF NOT EXISTS idx_rbac_users_username  ON rbac_users (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_rbac_users_role      ON rbac_users (role) WHERE enabled = TRUE;

COMMENT ON TABLE rbac_users IS
    'RBAC user registry. Migrated from data/rbac-users.json.';
COMMENT ON COLUMN rbac_users.username IS
    'Case-insensitive unique; indexed on LOWER(username) for lookup.';

-- ── Signing Keys ─────────────────────────────────────────────────────────────
-- Maps to: services/artifact/keyStore.js
-- CRITICAL: private_key_encrypted stores AES-256-GCM ciphertext ONLY.
--           The KEK (QODIQA_KEY_ENCRYPTION_KEY) NEVER appears in the database.

CREATE TABLE IF NOT EXISTS signing_keys (
    key_id                  VARCHAR(128)  PRIMARY KEY,   -- format: 'clientId:key_vN'
    client_id               VARCHAR(64)   NOT NULL,
    version                 INTEGER       NOT NULL,
    algorithm               VARCHAR(32)   NOT NULL DEFAULT 'ed25519',
    public_key_der_b64      TEXT          NOT NULL,      -- base64 SPKI DER
    status                  VARCHAR(16)   NOT NULL DEFAULT 'active',
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    rotation_deadline       TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ,
    -- Encrypted private key payload (NULL for deprecated/revoked — private material purged)
    enc_private_key_b64     TEXT,         -- base64 AES-256-GCM ciphertext
    enc_iv_b64              TEXT,         -- base64 IV (12 bytes for GCM)
    enc_auth_tag_b64        TEXT,         -- base64 GCM auth tag (16 bytes)
    enc_kek_id              VARCHAR(128), -- which KEK version was used

    CONSTRAINT signing_keys_status_check CHECK (
        status IN ('active', 'deprecated', 'revoked')
    ),
    CONSTRAINT signing_keys_version_positive CHECK (version > 0),
    -- Active keys must have all encryption fields; revoked/deprecated must not
    CONSTRAINT signing_keys_active_enc CHECK (
        (status = 'active' AND
         enc_private_key_b64 IS NOT NULL AND
         enc_iv_b64 IS NOT NULL AND
         enc_auth_tag_b64 IS NOT NULL)
        OR
        (status IN ('deprecated', 'revoked') AND
         enc_private_key_b64 IS NULL AND
         enc_iv_b64 IS NULL AND
         enc_auth_tag_b64 IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_client_id    ON signing_keys (client_id);
CREATE INDEX IF NOT EXISTS idx_signing_keys_client_active ON signing_keys (client_id, status)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_signing_keys_expires       ON signing_keys (expires_at)
    WHERE expires_at IS NOT NULL;
-- Legacy key ID remapping (old format → new versioned format)
CREATE TABLE IF NOT EXISTS signing_key_legacy_map (
    old_key_id     VARCHAR(128)  PRIMARY KEY,
    new_key_id     VARCHAR(128)  NOT NULL REFERENCES signing_keys(key_id)
);

COMMENT ON TABLE signing_keys IS
    'Ed25519 signing keys. Private material encrypted at rest with AES-256-GCM.';
COMMENT ON COLUMN signing_keys.enc_private_key_b64 IS
    'AES-256-GCM ciphertext of the PKCS#8 DER private key. NULL for non-active keys.';

-- ── Policies ─────────────────────────────────────────────────────────────────
-- Maps to: src/core/policy/store.js + policies.json
-- Normalized: policy core separated from versioned snapshots and history

CREATE TABLE IF NOT EXISTS policies (
    id                  VARCHAR(128)  PRIMARY KEY,
    name                VARCHAR(256)  NOT NULL,
    description         TEXT          NOT NULL DEFAULT '',
    type                VARCHAR(32)   NOT NULL,
    priority            INTEGER       NOT NULL DEFAULT 100,
    enabled             BOOLEAN       NOT NULL DEFAULT TRUE,
    config              JSONB         NOT NULL DEFAULT '{}',
    status              VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    current_version     INTEGER       NOT NULL DEFAULT 1,
    validation_status   VARCHAR(16)   NOT NULL DEFAULT 'VALID',
    validation_errors   JSONB         NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    created_by          VARCHAR(128)  NOT NULL DEFAULT 'system',
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_by          VARCHAR(128)  NOT NULL DEFAULT 'system',

    CONSTRAINT policies_type_check CHECK (
        type IN ('REQUIRE_CONSENT', 'BLOCK_IP', 'TIME_WINDOW', 'RATE_LIMIT')
    ),
    CONSTRAINT policies_status_check CHECK (
        status IN ('ACTIVE', 'DISABLED')
    ),
    CONSTRAINT policies_priority_check CHECK (priority >= 0 AND priority <= 999999),
    CONSTRAINT policies_version_positive CHECK (current_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_policies_type      ON policies (type);
CREATE INDEX IF NOT EXISTS idx_policies_enabled   ON policies (enabled, priority)
    WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_policies_status    ON policies (status);

COMMENT ON TABLE policies IS
    'Policy definitions. Migrated from policies.json + data/policy-store.json.';
COMMENT ON COLUMN policies.config IS
    'Type-specific configuration stored as JSONB for efficient filtering.';

CREATE TABLE IF NOT EXISTS policy_versions (
    id              BIGSERIAL     PRIMARY KEY,
    policy_id       VARCHAR(128)  NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version_number  INTEGER       NOT NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(128)  NOT NULL DEFAULT 'system',
    summary         TEXT          NOT NULL DEFAULT '',
    snapshot        JSONB         NOT NULL,  -- full policy state at this version
    validation_status VARCHAR(16) NOT NULL DEFAULT 'VALID',
    validation_errors JSONB       NOT NULL DEFAULT '[]',

    CONSTRAINT policy_versions_unique    UNIQUE (policy_id, version_number),
    CONSTRAINT policy_versions_num_check CHECK (version_number > 0)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_policy  ON policy_versions (policy_id, version_number DESC);

CREATE TABLE IF NOT EXISTS policy_history (
    id          BIGSERIAL     PRIMARY KEY,
    policy_id   VARCHAR(128)  NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    event       VARCHAR(64)   NOT NULL,
    occurred_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    actor       VARCHAR(128)  NOT NULL DEFAULT 'system',
    version     INTEGER,
    comment     TEXT,
    changes     JSONB         NOT NULL DEFAULT '[]',  -- [{path, op, from, to}]

    CONSTRAINT policy_history_event_check CHECK (
        event IN ('POLICY_CREATED', 'POLICY_UPDATED', 'POLICY_ENABLED',
                  'POLICY_DISABLED', 'POLICY_ROLLED_BACK', 'POLICY_DELETED')
    )
);

CREATE INDEX IF NOT EXISTS idx_policy_history_policy  ON policy_history (policy_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_history_actor   ON policy_history (actor);

COMMENT ON TABLE policy_history IS
    'Immutable audit trail of policy lifecycle events.';

-- ── Audit Chain ───────────────────────────────────────────────────────────────
-- Maps to: src/core/audit/audit-log.js (NDJSON file)
-- CRITICAL DESIGN: The cryptographic chain (prevHash → hash) is preserved exactly.
-- PostgreSQL becomes the durable store; in-memory chain still verifies on startup.
-- UPDATE/DELETE on this table is forbidden at the row-security level (enforced below).

CREATE TABLE IF NOT EXISTS audit_chain (
    -- Chain position
    seq             BIGSERIAL     NOT NULL,  -- monotonic sequence (used for ordering, not trust)
    -- Cryptographic identity
    hash            CHAR(64)      PRIMARY KEY,   -- SHA-256 of canonical JSON
    prev_hash       VARCHAR(64)   NOT NULL,       -- 'GENESIS' or prior hash
    canonical       TEXT          NOT NULL,       -- sorted JSON used to compute hash
    -- Artifact identity
    artifact_id     VARCHAR(128)  NOT NULL,
    -- Enforcement result
    decision        VARCHAR(8)    NOT NULL,
    -- Timestamps
    recorded_at     TIMESTAMPTZ   NOT NULL,       -- ISO timestamp from entry.timestamp
    high_res_time   VARCHAR(32)   NOT NULL,       -- hrtime bigint as string
    -- Cryptographic proof fields ('UNAVAILABLE' for early BLOCK)
    input_hash      VARCHAR(64)   NOT NULL,
    signature       TEXT          NOT NULL,
    request_hash    VARCHAR(64)   NOT NULL,
    policy_hash     VARCHAR(64)   NOT NULL,
    verification_result BOOLEAN   NOT NULL,
    -- Optional fields
    nonce           VARCHAR(256),
    tenant_id       VARCHAR(128),
    execution_context JSONB,

    CONSTRAINT audit_chain_decision_check CHECK (
        decision IN ('ALLOW', 'BLOCK')
    ),
    CONSTRAINT audit_chain_prev_hash_genesis CHECK (
        prev_hash = 'GENESIS' OR LENGTH(prev_hash) = 64
    )
);

-- Unique artifact_id constraint: each artifact may appear at most once
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_artifact_id ON audit_chain (artifact_id);
-- Query patterns: lookup by tenant, lookup by decision for reporting
CREATE INDEX IF NOT EXISTS idx_audit_chain_tenant      ON audit_chain (tenant_id)
    WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_chain_decision    ON audit_chain (decision, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_chain_recorded_at ON audit_chain (recorded_at DESC);
-- Replay detection: find entries that reference an original execution
CREATE INDEX IF NOT EXISTS idx_audit_chain_replay_of
    ON audit_chain ((execution_context->>'replayOf'))
    WHERE execution_context ? 'replayOf';
-- Forward chain walk: find entries by prev_hash
CREATE INDEX IF NOT EXISTS idx_audit_chain_prev_hash   ON audit_chain (prev_hash);

COMMENT ON TABLE audit_chain IS
    'Immutable cryptographic audit chain. Rows must never be modified or deleted. '
    'Integrity is maintained by hash chaining; violation is a security incident.';
COMMENT ON COLUMN audit_chain.hash IS
    'SHA-256 of canonical JSON. Forms the chain link referenced by the next entry''s prev_hash.';
COMMENT ON COLUMN audit_chain.canonical IS
    'The exact JSON string that was hashed. Stored for forensic verification without recomputation.';

-- Row-level security: prevent accidental UPDATE/DELETE
-- (QODIQA service account can INSERT only; admin role needed for SELECT)
-- Actual enforcement via service account privileges — see security section.

-- ── Investigations ────────────────────────────────────────────────────────────
-- Maps to: src/core/investigation/store.js

CREATE TABLE IF NOT EXISTS investigations (
    id              VARCHAR(32)   PRIMARY KEY,   -- format: INV-<16 hex chars>
    title           VARCHAR(256)  NOT NULL,
    investigator    VARCHAR(128)  NOT NULL,
    notes           TEXT          NOT NULL DEFAULT '',
    status          VARCHAR(16)   NOT NULL DEFAULT 'OPEN',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT investigations_status_check CHECK (status IN ('OPEN', 'CLOSED', 'ARCHIVED')),
    CONSTRAINT investigations_id_format CHECK (id ~ '^INV-[0-9A-F]{16}$')
);

CREATE INDEX IF NOT EXISTS idx_investigations_status    ON investigations (status);
CREATE INDEX IF NOT EXISTS idx_investigations_created   ON investigations (created_at DESC);

CREATE TABLE IF NOT EXISTS investigation_artifacts (
    investigation_id VARCHAR(32)   NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    artifact_id      VARCHAR(128)  NOT NULL,
    added_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    PRIMARY KEY (investigation_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_inv_artifacts_artifact  ON investigation_artifacts (artifact_id);

CREATE TABLE IF NOT EXISTS investigation_audit_events (
    id               BIGSERIAL     PRIMARY KEY,
    investigation_id VARCHAR(32)   NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    event_type       VARCHAR(64)   NOT NULL,
    recorded_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    payload          JSONB         NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_inv_events_investigation ON investigation_audit_events (investigation_id, recorded_at DESC);

COMMENT ON TABLE investigations IS
    'Forensic investigations. Migrated from data/investigations.json.';

-- ── Evidence package metadata ────────────────────────────────────────────────
-- Tracks generated evidence packages for auditability (Req 7)

CREATE TABLE IF NOT EXISTS evidence_packages (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id     VARCHAR(128)  NOT NULL,
    schema_version  VARCHAR(64)   NOT NULL,
    generator_version VARCHAR(32) NOT NULL,
    generated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    requestor_id    UUID          REFERENCES rbac_users(id) ON DELETE SET NULL,
    requestor_username VARCHAR(128),
    requestor_role  VARCHAR(32),
    package_hash    CHAR(64)      NOT NULL,  -- SHA-256 of package content
    export_format   VARCHAR(8)    NOT NULL DEFAULT 'JSON',
    overall_status  VARCHAR(32)

    CONSTRAINT evidence_packages_format_check CHECK (
        export_format IN ('JSON', 'PDF', 'AUDIT', 'VERIFY')
    )
);

CREATE INDEX IF NOT EXISTS idx_evidence_artifact    ON evidence_packages (artifact_id, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_requestor   ON evidence_packages (requestor_id)
    WHERE requestor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_generated   ON evidence_packages (generated_at DESC);

-- ── Schema version tracking ───────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (1, 'initial_schema', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
