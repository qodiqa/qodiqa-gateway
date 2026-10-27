-- Migration 011: Transparency Log (Component #22)
--
-- Establishes the append-only transparency log that provides tamper-evident,
-- publicly verifiable, cryptographically signed records of every significant
-- event in the QODIQA evidence lifecycle.
--
-- Architecture:
--   transparency_log_entries   — immutable append-only ledger of signed entries
--   transparency_roots         — periodic root digests covering entry ranges
--   transparency_verifications — audit log of every verification run
--
-- Hash chain design (entries):
--   entry_hash = SHA-256("QODIQA::TRANSPARENCY::V1" || canonical JSON of {
--     transparencyId, entryType, artifactId, evidenceChainId, verificationId,
--     payloadHash, previousEntryHash, signerKeyId
--   })
--   Chain: entry[n].previousEntryHash === entry[n-1].entry_hash
--
-- Root design:
--   root_hash = RFC6962 Merkle root over entry_hashes[seqFrom..seqTo].
--     leaf_hash(e) = SHA-256(0x00 || bytes(e))
--     node_hash(l,r) = SHA-256(0x01 || l || r)
--   Signed separately over canonical root metadata.
--   Roots chain: root[n].previousRootHash === root[n-1].root_hash
--
-- Immutability enforcement:
--   • No UPDATE or DELETE policies (RLS INSERT-only for both roles).
--   • UNIQUE constraint on entry_hash prevents hash reuse.
--   • UNIQUE constraint on transparency_id (external stable reference).
--
-- Integrates with: evidence_chain_records, audit_chain, signing_keys.
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.

BEGIN;

-- ── Transparency Log Entries ──────────────────────────────────────────────────
--
-- Immutable append-only ledger. One row per registered event.
-- INSERT-only. No UPDATE or DELETE.

CREATE TABLE IF NOT EXISTS transparency_log_entries (
  id                    BIGSERIAL     PRIMARY KEY,

  -- Stable external identifier
  transparency_id       UUID          NOT NULL DEFAULT gen_random_uuid(),

  -- Classification
  entry_type            VARCHAR(64)   NOT NULL,

  -- Cross-system content links (all nullable — not every entry covers all three)
  artifact_id           VARCHAR(128)  NULL,
  evidence_chain_id     UUID          NULL,          -- evidence_chain_records.evidence_id
  verification_id       BIGINT        NULL,          -- evidence_chain_verifications.id

  -- Payload
  payload               JSONB         NOT NULL DEFAULT '{}',
  payload_hash          CHAR(64)      NOT NULL,      -- SHA-256 of canonical(payload)

  -- Hash chain
  previous_entry_hash   VARCHAR(64)   NULL,          -- NULL for genesis entry
  entry_hash            CHAR(64)      NOT NULL,      -- domain-separated SHA-256 of canonical fields

  -- Signing
  signer_key_id         VARCHAR(128)  NOT NULL,
  signer_key_version    INTEGER       NULL,
  signature             TEXT          NOT NULL,      -- base64-encoded Ed25519 signature

  -- Metadata
  registered_by         VARCHAR(128)  NOT NULL DEFAULT 'system',
  tenant_id             VARCHAR(128)  NULL,
  created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT tle_transparency_id_unique  UNIQUE (transparency_id),
  CONSTRAINT tle_entry_hash_unique       UNIQUE (entry_hash),
  CONSTRAINT tle_payload_hash_length     CHECK (LENGTH(payload_hash) = 64),
  CONSTRAINT tle_entry_hash_length       CHECK (LENGTH(entry_hash) = 64),
  CONSTRAINT tle_signature_nonempty      CHECK (LENGTH(signature) > 0),
  CONSTRAINT tle_entry_type_valid        CHECK (entry_type IN (
    'ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM'
  ))
);

COMMENT ON TABLE transparency_log_entries IS
  'Immutable cryptographic transparency log. One row per registered event. '
  'Entries are cryptographically chained and signed. '
  'No UPDATE or DELETE permitted at any layer. '
  'entry_hash chain enables end-to-end tamper detection.';

COMMENT ON COLUMN transparency_log_entries.entry_hash IS
  'Domain-separated SHA-256 of canonical entry fields. '
  'Chain: entry[n].previous_entry_hash === entry[n-1].entry_hash.';

COMMENT ON COLUMN transparency_log_entries.payload_hash IS
  'SHA-256 of the canonical JSON of the payload field. '
  'Enables payload integrity verification without loading full JSONB.';

COMMENT ON COLUMN transparency_log_entries.signature IS
  'Base64-encoded Ed25519 signature over the entry_hash bytes '
  'using signer_key_id at registration time.';

-- ── Indexes — Entries ─────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_tle_transparency_id
  ON transparency_log_entries (transparency_id);

CREATE INDEX IF NOT EXISTS idx_tle_artifact_id
  ON transparency_log_entries (artifact_id, created_at DESC)
  WHERE artifact_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tle_evidence_chain_id
  ON transparency_log_entries (evidence_chain_id)
  WHERE evidence_chain_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tle_entry_type
  ON transparency_log_entries (entry_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tle_created_at
  ON transparency_log_entries (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tle_signer_key_id
  ON transparency_log_entries (signer_key_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tle_tenant
  ON transparency_log_entries (tenant_id, created_at DESC)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tle_prev_hash
  ON transparency_log_entries (previous_entry_hash)
  WHERE previous_entry_hash IS NOT NULL;

-- ── Transparency Roots ────────────────────────────────────────────────────────
--
-- Periodic root digests that cover a contiguous range of entries.
-- Immutable — INSERT-only.

CREATE TABLE IF NOT EXISTS transparency_roots (
  id                   BIGSERIAL     PRIMARY KEY,

  -- Stable external identifier
  root_id              UUID          NOT NULL DEFAULT gen_random_uuid(),

  -- Range covered by this root
  seq_from             BIGINT        NOT NULL,  -- id of first entry in range
  seq_to               BIGINT        NOT NULL,  -- id of last entry in range
  entry_count          INTEGER       NOT NULL,

  -- Root digest
  root_hash            CHAR(64)      NOT NULL,  -- SHA-256 of all entry hashes in range (ordered)

  -- Root chain link
  previous_root_hash   VARCHAR(64)   NULL,      -- root_hash of the immediately preceding root

  -- Signing
  signature            TEXT          NOT NULL,  -- Ed25519 over canonical root metadata
  signer_key_id        VARCHAR(128)  NOT NULL,

  -- Metadata
  generated_by         VARCHAR(128)  NOT NULL DEFAULT 'system',
  generated_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT tr_root_id_unique    UNIQUE (root_id),
  CONSTRAINT tr_root_hash_unique  UNIQUE (root_hash),
  CONSTRAINT tr_seq_unique        UNIQUE (seq_from, seq_to),
  CONSTRAINT tr_root_hash_length  CHECK (LENGTH(root_hash) = 64),
  CONSTRAINT tr_count_positive    CHECK (entry_count > 0),
  CONSTRAINT tr_seq_range_valid   CHECK (seq_to >= seq_from)
);

COMMENT ON TABLE transparency_roots IS
  'Periodic root digests that commit a contiguous range of transparency log entries. '
  'root_hash is an RFC6962-compatible Merkle root over entry_hashes[seqFrom..seqTo]. '
  'Roots are chained via previous_root_hash. '
  'INSERT-only: root history must never be modified or deleted.';

COMMENT ON COLUMN transparency_roots.root_hash IS
  'RFC6962 Merkle root: leaf_hash(e)=SHA256(0x00||e), node_hash(l,r)=SHA256(0x01||l||r). '
  'Reproducible by any party with access to the ordered entry list and merkle.js.';

COMMENT ON COLUMN transparency_roots.signature IS
  'Base64-encoded Ed25519 signature over SHA-256 of canonical root metadata '
  '(rootId, seqFrom, seqTo, entryCount, rootHash, previousRootHash).';

-- ── Indexes — Roots ───────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_tr_root_id
  ON transparency_roots (root_id);

CREATE INDEX IF NOT EXISTS idx_tr_generated_at
  ON transparency_roots (generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_tr_seq_range
  ON transparency_roots (seq_from, seq_to);

-- ── Transparency Verifications ────────────────────────────────────────────────
--
-- Immutable audit log of every verification run.
-- INSERT-only.

CREATE TABLE IF NOT EXISTS transparency_verifications (
  id                   BIGSERIAL     PRIMARY KEY,
  transparency_id      UUID          NULL,           -- entry being verified (if single-entry)
  verification_type    VARCHAR(32)   NOT NULL,       -- ENTRY, CHAIN, ROOT, PROOF
  verification_result  VARCHAR(16)   NOT NULL,       -- VALID, INVALID, PARTIAL, ERROR
  checks_performed     JSONB         NOT NULL DEFAULT '[]',
  failed_check         VARCHAR(64)   NULL,
  failure_reason       TEXT          NULL,
  verified_by          VARCHAR(128)  NOT NULL DEFAULT 'system',
  duration_ms          INTEGER       NULL,
  verified_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  CONSTRAINT tv_result_check CHECK (verification_result IN ('VALID', 'INVALID', 'PARTIAL', 'ERROR')),
  CONSTRAINT tv_type_check   CHECK (verification_type IN ('ENTRY', 'CHAIN', 'ROOT', 'PROOF'))
);

COMMENT ON TABLE transparency_verifications IS
  'Immutable log of every transparency verification run. '
  'INSERT-only: verification history must never be modified or deleted.';

-- ── Indexes — Verifications ───────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_tv_transparency_id
  ON transparency_verifications (transparency_id, verified_at DESC)
  WHERE transparency_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tv_result
  ON transparency_verifications (verification_result, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_tv_type
  ON transparency_verifications (verification_type, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_tv_verified_at
  ON transparency_verifications (verified_at DESC);

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE transparency_log_entries     ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_roots           ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_verifications   ENABLE ROW LEVEL SECURITY;

ALTER TABLE transparency_log_entries     FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_roots           FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_verifications   FORCE ROW LEVEL SECURITY;

-- SELECT: all authenticated roles
CREATE POLICY tle_select
  ON transparency_log_entries
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

CREATE POLICY tr_select
  ON transparency_roots
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

CREATE POLICY tv_select
  ON transparency_verifications
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

-- INSERT-only (no UPDATE, no DELETE)
CREATE POLICY tle_insert
  ON transparency_log_entries
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY tr_insert
  ON transparency_roots
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY tv_insert
  ON transparency_verifications
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON transparency_log_entries   TO qodiqa_app;
GRANT SELECT         ON transparency_log_entries   TO qodiqa_read;
GRANT SELECT, INSERT ON transparency_roots         TO qodiqa_app;
GRANT SELECT         ON transparency_roots         TO qodiqa_read;
GRANT SELECT, INSERT ON transparency_verifications TO qodiqa_app;
GRANT SELECT         ON transparency_verifications TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE transparency_log_entries_id_seq    TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE transparency_roots_id_seq          TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE transparency_verifications_id_seq  TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (11, 'transparency_log', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
