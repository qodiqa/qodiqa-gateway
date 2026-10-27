#!/usr/bin/env node
'use strict';

/**
 * Webhook Secret KEK Migration — remediation
 *
 * Background: before this fix, src/core/webhooks/webhookSecrets.js read
 * process.env.QODIQA_KEY_ENCRYPTION_KEY directly instead of going through
 * secretsProvider.js. Deployments running an external KMS backend
 * (QODIQA_KMS_PROVIDER=vault-kv / vault-transit / aws-kms / azure-kv /
 * gcp-kms / hsm) either had webhook encryption throw at runtime, or an
 * operator worked around that by keeping the raw env var populated — in
 * which case existing webhook_endpoints rows were encrypted under that raw
 * env-var KEK, NOT the KMS-derived KEK the rest of the platform uses.
 *
 * Now that webhookSecrets.js resolves its KEK through secretsProvider (wired
 * to the real KMS backend at startup), any row still encrypted under the old
 * raw env-var KEK will fail to decrypt. This script finds those rows and
 * re-encrypts them under the correct, currently-configured KEK.
 *
 * This script reuses webhookSecrets.encryptSecret()/decryptSecret() for every
 * cryptographic operation — it contains no independent crypto implementation.
 * It works by temporarily pointing secretsProvider at the legacy KEK via the
 * same _setExternalKek()/_clearCache() hooks keyProviderFactory itself uses,
 * so both the legacy decrypt and the new encrypt flow through the one
 * authoritative encryption path.
 *
 * Safety:
 *   - Defaults to DRY RUN. Pass --execute to actually write.
 *   - Idempotent: rows already decryptable under the current KEK (this is
 *     ALL rows for QODIQA_KMS_PROVIDER=local, since the env var IS the KEK
 *     in that mode) are left untouched and reported as "already current".
 *   - Never logs plaintext secrets or KEK material, only outcomes.
 *   - A row that fails under both the current and legacy KEK is left
 *     untouched and reported as FAILED for manual investigation — the
 *     script never deletes or discards ciphertext it cannot verify.
 *
 * Usage:
 *   QODIQA_PG_ENABLED=true QODIQA_KMS_PROVIDER=aws-kms \
 *     QODIQA_KEY_ENCRYPTION_KEY=<legacy hex KEK> \
 *     node scripts/migrate-webhook-secrets-kek.js              # dry run
 *
 *   QODIQA_PG_ENABLED=true QODIQA_KMS_PROVIDER=aws-kms \
 *     QODIQA_KEY_ENCRYPTION_KEY=<legacy hex KEK> \
 *     node scripts/migrate-webhook-secrets-kek.js --execute     # apply
 *
 * QODIQA_KEY_ENCRYPTION_KEY here is the OLD raw KEK the deployment used
 * before/while working around the bug — required only to recover rows that
 * need migrating. It is read once, used solely as the legacy decrypt key,
 * and never written anywhere. If it is not set, rows that need it are
 * reported as FAILED with instructions instead of being silently skipped.
 */

require('dotenv').config();

const EXECUTE = process.argv.includes('--execute');

function log(level, msg, data = {}) {
  const prefix = { INFO: '✓', WARN: '⚠', ERROR: '✗' }[level] ?? '·';
  const extra  = Object.keys(data).length ? `  ${JSON.stringify(data)}` : '';
  console.log(`${prefix} ${msg}${extra}`);
}

/**
 * Pure per-row migration decision, isolated from I/O for testability.
 * Reuses webhookSecrets.encryptSecret()/decryptSecret() exclusively — no
 * independent crypto implementation exists in this script.
 *
 * @param {{ secret_enc: string, secret_iv: string, secret_tag: string }} row
 * @param {Buffer} targetKek        Current, correctly-configured KEK (from secretsProvider)
 * @param {Buffer|null} legacyKek   Old raw env-var KEK, if provided
 * @param {{ secretsProvider: object, webhookSecrets: object }} deps
 * @returns {{ outcome: 'already-current'|'migrated'|'failed', update: ({enc:string,iv:string,tag:string}|null) }}
 */
function _migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets }) {
  secretsProvider._setExternalKek(targetKek);
  try {
    webhookSecrets.decryptSecret(row.secret_enc, row.secret_iv, row.secret_tag);
    return { outcome: 'already-current', update: null };
  } catch (_) {
    // Falls through to legacy-KEK recovery below.
  }

  if (!legacyKek) {
    return { outcome: 'failed', update: null };
  }

  let plaintext;
  secretsProvider._setExternalKek(legacyKek);
  try {
    plaintext = webhookSecrets.decryptSecret(row.secret_enc, row.secret_iv, row.secret_tag);
  } catch (_) {
    return { outcome: 'failed', update: null };
  } finally {
    secretsProvider._setExternalKek(targetKek);
  }

  const update = webhookSecrets.encryptSecret(plaintext);
  plaintext = null;
  return { outcome: 'migrated', update };
}

async function main() {
  const pgPool          = require('../src/infra/postgres/pool');
  const kpf              = require('../src/infra/keys/keyProviderFactory');
  const secretsProvider  = require('../services/secrets/secretsProvider');
  const webhookSecrets   = require('../src/core/webhooks/webhookSecrets');

  log('INFO', EXECUTE ? 'Starting migration (writes enabled)' : 'DRY RUN — no writes will occur (pass --execute to apply)');

  pgPool.initialize();
  if (!pgPool.isEnabled()) {
    log('ERROR', 'PostgreSQL backend is not enabled. Set QODIQA_PG_ENABLED=true and connection env vars.');
    process.exitCode = 1;
    return;
  }

  // Preserve the legacy raw KEK (if present) BEFORE keyProviderFactory
  // initializes — initialize() doesn't consume this var except for the
  // 'local' provider, but we capture it defensively regardless.
  const legacyKekHex = process.env.QODIQA_KEY_ENCRYPTION_KEY || null;
  let legacyKek = null;
  if (legacyKekHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(legacyKekHex)) {
      log('ERROR', 'QODIQA_KEY_ENCRYPTION_KEY is set but is not 64 hex characters — cannot use as legacy KEK.');
      process.exitCode = 1;
      return;
    }
    legacyKek = Buffer.from(legacyKekHex, 'hex');
  }

  try {
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();
  } catch (err) {
    log('ERROR', `Failed to initialize the configured KMS provider: ${err.message}`);
    process.exitCode = 1;
    return;
  }

  const targetKek = secretsProvider.getKeyEncryptionKey();
  log('INFO', 'Target KEK resolved via secretsProvider', {
    provider: secretsProvider.getProviderName(),
  });

  const result = await pgPool.query(
    'SELECT id, tenant_id, secret_enc, secret_iv, secret_tag FROM webhook_endpoints',
  );
  const rows = result.rows;
  log('INFO', `Found ${rows.length} webhook endpoint(s) to check`);

  let alreadyCurrent = 0;
  let migrated       = 0;
  let failed          = 0;
  const failedIds     = [];

  for (const row of rows) {
    const { outcome, update } = _migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });

    if (outcome === 'already-current') {
      alreadyCurrent++;
      continue;
    }

    if (outcome === 'failed') {
      const reason = legacyKek
        ? 'not decryptable under EITHER the current or legacy KEK — needs manual investigation'
        : 'not decryptable under current KEK and no legacy KEK was provided (set QODIQA_KEY_ENCRYPTION_KEY to the old raw KEK and re-run)';
      log(legacyKek ? 'ERROR' : 'WARN', `Row ${reason}`, { id: row.id, tenantId: row.tenant_id });
      failed++;
      failedIds.push(row.id);
      continue;
    }

    // outcome === 'migrated'
    if (EXECUTE) {
      await pgPool.query(
        `UPDATE webhook_endpoints
            SET secret_enc = $1, secret_iv = $2, secret_tag = $3, updated_at = NOW()
          WHERE id = $4`,
        [update.enc, update.iv, update.tag, row.id],
      );
    }
    log('INFO', EXECUTE ? 'Migrated' : 'Would migrate', { id: row.id, tenantId: row.tenant_id });
    migrated++;
  }

  log('INFO', 'Summary', { total: rows.length, alreadyCurrent, migrated, failed });
  if (failed > 0) {
    log('WARN', 'Some rows require manual investigation', { ids: failedIds });
    process.exitCode = 1;
  }
}

module.exports = { _migrateRow };

if (require.main === module) {
  main()
    .catch((err) => {
      log('ERROR', `Migration FAILED: ${err.message}`);
      console.error(err.stack);
      process.exitCode = 1;
    })
    .finally(async () => {
      try {
        const pgPool = require('../src/infra/postgres/pool');
        await pgPool.shutdown();
      } catch (_) { /* best-effort */ }
    });
}
