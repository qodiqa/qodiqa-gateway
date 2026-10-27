-- QODIQA PostgreSQL Migration 030
-- remediation: corrects schema-level documentation left over from the
-- webhook secret encryption bug. Migration 016's table/column comments
-- hard-coded "The KEK is QODIQA_KEY_ENCRYPTION_KEY" — that was accurate only
-- for the (buggy) direct-env-read implementation in
-- src/core/webhooks/webhookSecrets.js. That code now resolves its KEK
-- through secretsProvider.js, the same provider-agnostic abstraction used
-- by every other encrypted-at-rest secret class (Vault, HSM, AWS/Azure/GCP
-- KMS, or the local env var, depending on QODIQA_KMS_PROVIDER).
--
-- No schema or data change — COMMENT ON is metadata-only and does not touch
-- webhook_endpoints rows. This corrects the documentation without editing
-- the already-applied migration 016.

BEGIN;

COMMENT ON TABLE webhook_endpoints IS
  'Per-tenant webhook endpoint subscriptions. '
  'Secrets are stored AES-256-GCM encrypted — never in plaintext. '
  'The key encryption key (KEK) is resolved via services/secrets/secretsProvider.js, '
  'the same provider-agnostic abstraction (local env var, Vault, HSM, or cloud KMS, '
  'per QODIQA_KMS_PROVIDER) used for every other encrypted-at-rest secret. '
  'Plaintext is returned once at creation only.';

COMMENT ON COLUMN webhook_endpoints.secret_enc IS
  'AES-256-GCM ciphertext of the plaintext webhook signing secret (base64). '
  'Encrypted via src/core/webhooks/webhookSecrets.js using the KEK resolved '
  'from services/secrets/secretsProvider.js (provider-agnostic — see QODIQA_KMS_PROVIDER).';

COMMENT ON COLUMN webhook_endpoints.secret_iv IS
  'AES-256-GCM 12-byte initialization vector for the secret (base64).';

COMMENT ON COLUMN webhook_endpoints.secret_tag IS
  'AES-256-GCM 16-byte authentication tag for the secret (base64).';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (30, 'webhook_kek_abstraction_doc_fix', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
