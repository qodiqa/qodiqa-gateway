'use strict';

/**
 * Centralized KMS/Vault configuration validation (item 21).
 *
 * Every field validated here mirrors what its provider file (./providers/*)
 * already enforces at initialize() time — this module does not invent new
 * requirements, it moves the same checks earlier and gives each one a
 * distinct, exact-field FATAL instead of an ad hoc per-provider Error
 * surfacing deep inside an async initialize() call.
 *
 * Modeled on src/core/rateLimit/config.js's pattern (z.object + safeParse +
 * emit('FATAL', ...) + throw), NOT on the request-body `.strict()` convention
 * from item 9 — item 9 itself scoped `.strict()` to HTTP request-validation
 * schemas and explicitly excluded rateLimit/config.js's startup-config usage
 * as a different category. `.strict()` has no meaningful application here:
 * this module builds its own raw object from a fixed, known set of env var
 * names per provider — there is no caller-controlled key set to reject
 * unknown keys from.
 *
 * An unrecognized QODIQA_KMS_PROVIDER value is deliberately NOT validated
 * here — keyProviderFactory.js's own provider-selection switch already
 * throws a clear "unknown KEK provider "X". Valid values: ..." error; this
 * module would only be able to duplicate that message, not improve it, so
 * validateKmsConfig() no-ops for unrecognized provider names and lets that
 * existing error stand as the single source of truth.
 */

const { z }    = require('../../validation/zod');
const { emit } = require('../../../services/logger');

const KNOWN_PROVIDERS = Object.freeze([
  'local', 'vault-kv', 'vault-transit', 'aws-kms', 'azure-kv', 'gcp-kms', 'hsm',
]);

// ── Per-provider schemas ────────────────────────────────────────────────────
// Field names and requiredness match's source inventory exactly:
//   local          — src/infra/keys/providers/local.js
//   vault-kv/-transit — src/infra/keys/providers/vault.js
//   aws-kms        — src/infra/keys/providers/awsKms.js
//   azure-kv       — src/infra/keys/providers/azureKeyVault.js
//   gcp-kms        — src/infra/keys/providers/gcpKms.js
//   hsm            — src/infra/keys/providers/hsm.js

const localSchema = z.object({
  provider: z.literal('local'),
});

// Shared by vault-kv and vault-transit: vault.js's _buildVaultClient() throws
// "no Vault credentials configured" unless EITHER a full AppRole pair
// (VAULT_ROLE_ID + VAULT_SECRET_ID) or VAULT_TOKEN is present — and throws a
// less specific error if only one half of the AppRole pair is set (that half
// alone is silently ignored by vault.js today, which is worth a clearer
// message here even though vault.js itself doesn't distinguish it).
function _vaultAuthRefinement(data, ctx) {
  const hasAppRole = !!(data.VAULT_ROLE_ID && data.VAULT_SECRET_ID);
  const hasToken   = !!data.VAULT_TOKEN;

  if (data.VAULT_ROLE_ID && !data.VAULT_SECRET_ID) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      path:    ['VAULT_SECRET_ID'],
      message: 'VAULT_SECRET_ID is not set — required alongside VAULT_ROLE_ID for AppRole authentication.',
    });
  } else if (data.VAULT_SECRET_ID && !data.VAULT_ROLE_ID) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      path:    ['VAULT_ROLE_ID'],
      message: 'VAULT_ROLE_ID is not set — required alongside VAULT_SECRET_ID for AppRole authentication.',
    });
  } else if (!hasAppRole && !hasToken) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      path:    ['VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_TOKEN'],
      message: 'No Vault credentials configured — set VAULT_ROLE_ID + VAULT_SECRET_ID (preferred) or VAULT_TOKEN.',
    });
  }
}

const vaultKvSchema = z.object({
  provider:           z.literal('vault-kv'),
  VAULT_ADDR:         z.string().optional(),
  VAULT_TOKEN:        z.string().optional(),
  VAULT_ROLE_ID:      z.string().optional(),
  VAULT_SECRET_ID:    z.string().optional(),
  VAULT_NAMESPACE:    z.string().optional(),
  VAULT_KEK_PATH:     z.string().optional(),
  VAULT_KEK_MOUNT:    z.string().optional(),
  VAULT_TLS_CA_CERT:  z.string().optional(),
});

const vaultTransitSchema = z.object({
  provider:            z.literal('vault-transit'),
  VAULT_ADDR:          z.string().optional(),
  VAULT_TOKEN:         z.string().optional(),
  VAULT_ROLE_ID:       z.string().optional(),
  VAULT_SECRET_ID:     z.string().optional(),
  VAULT_NAMESPACE:     z.string().optional(),
  VAULT_TRANSIT_MOUNT: z.string().optional(),
  VAULT_TLS_CA_CERT:   z.string().optional(),
});

const awsKmsSchema = z.object({
  provider:        z.literal('aws-kms'),
  AWS_KMS_KEY_ID:  z.string({ error: (iss) => (iss.input === undefined ? 'AWS_KMS_KEY_ID is not set.' : undefined) })
                     .min(1, 'AWS_KMS_KEY_ID is not set.'),
  AWS_KMS_REGION:  z.string({ error: (iss) => (iss.input === undefined ? 'AWS_KMS_REGION is not set.' : undefined) })
                     .min(1, 'AWS_KMS_REGION is not set.'),
  AWS_KMS_EDK_PATH: z.string().optional(),
});

const azureKvSchema = z.object({
  provider:                 z.literal('azure-kv'),
  AZURE_KEY_VAULT_URI:      z.string({ error: (iss) => (iss.input === undefined ? 'AZURE_KEY_VAULT_URI is not set.' : undefined) })
                              .min(1, 'AZURE_KEY_VAULT_URI is not set.'),
  AZURE_KEY_VAULT_KEY_NAME: z.string({ error: (iss) => (iss.input === undefined ? 'AZURE_KEY_VAULT_KEY_NAME is not set.' : undefined) })
                              .min(1, 'AZURE_KEY_VAULT_KEY_NAME is not set.'),
  AZURE_KEY_VAULT_KEY_VER:  z.string().optional(),
  AZURE_WRAPPED_KEY_PATH:   z.string().optional(),
});

const gcpKmsSchema = z.object({
  provider:            z.literal('gcp-kms'),
  GCP_KMS_PROJECT:     z.string({ error: (iss) => (iss.input === undefined ? 'GCP_KMS_PROJECT is not set.' : undefined) })
                         .min(1, 'GCP_KMS_PROJECT is not set.'),
  GCP_KMS_KEYRING:     z.string({ error: (iss) => (iss.input === undefined ? 'GCP_KMS_KEYRING is not set.' : undefined) })
                         .min(1, 'GCP_KMS_KEYRING is not set.'),
  GCP_KMS_KEY:         z.string({ error: (iss) => (iss.input === undefined ? 'GCP_KMS_KEY is not set.' : undefined) })
                         .min(1, 'GCP_KMS_KEY is not set.'),
  GCP_KMS_LOCATION:    z.string().optional(),
  GCP_KMS_KEY_VERSION: z.string().optional(),
  // Not enforced by gcpKms.js itself (an invalid value silently falls into
  // the asymmetric branch) — validated here as a proactive safety net since
  // a typo would otherwise misroute every encrypt/decrypt call silently.
  GCP_KMS_KEY_TYPE:    z.enum(['symmetric', 'asymmetric'], {
                         error: () => 'GCP_KMS_KEY_TYPE must be "symmetric" or "asymmetric".',
                       }).optional(),
  GCP_WRAPPED_KEY_PATH: z.string().optional(),
});

const hsmSchema = z.object({
  provider:            z.literal('hsm'),
  HSM_PKCS11_LIB:      z.string({ error: (iss) => (iss.input === undefined ? 'HSM_PKCS11_LIB is not set.' : undefined) })
                         .min(1, 'HSM_PKCS11_LIB is not set.'),
  HSM_PKCS11_SLOT:     z.string().optional(),
  HSM_PKCS11_PIN:      z.string().optional(),
  HSM_PKCS11_PIN_FILE: z.string().optional(),
  HSM_KEY_INDEX_PATH:  z.string().optional(),
});

function _hsmPinRefinement(data, ctx) {
  if (!data.HSM_PKCS11_PIN && !data.HSM_PKCS11_PIN_FILE) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      path:    ['HSM_PKCS11_PIN', 'HSM_PKCS11_PIN_FILE'],
      message: 'No PIN configured — set HSM_PKCS11_PIN or HSM_PKCS11_PIN_FILE.',
    });
  }
}

// Cross-field refinements (Vault auth, HSM PIN) are applied to the UNION as
// a whole, not to the individual branch schemas — z.discriminatedUnion()
// requires each member to be a plain ZodObject exposing .shape; a branch
// wrapped in its own .superRefine() becomes a ZodEffects, which does not,
// and breaks the union's discriminator lookup.
const KmsConfigSchema = z.discriminatedUnion('provider', [
  localSchema,
  vaultKvSchema,
  vaultTransitSchema,
  awsKmsSchema,
  azureKvSchema,
  gcpKmsSchema,
  hsmSchema,
]).superRefine((data, ctx) => {
  if (data.provider === 'vault-kv' || data.provider === 'vault-transit') {
    _vaultAuthRefinement(data, ctx);
  } else if (data.provider === 'hsm') {
    _hsmPinRefinement(data, ctx);
  }
});

// ── Raw env → schema-shaped object ──────────────────────────────────────────

function _pick(names) {
  const obj = {};
  for (const name of names) {
    if (process.env[name] !== undefined) obj[name] = process.env[name];
  }
  return obj;
}

const _FIELDS_BY_PROVIDER = {
  'local':          [],
  'vault-kv':       ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_NAMESPACE', 'VAULT_KEK_PATH', 'VAULT_KEK_MOUNT', 'VAULT_TLS_CA_CERT'],
  'vault-transit':  ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_NAMESPACE', 'VAULT_TRANSIT_MOUNT', 'VAULT_TLS_CA_CERT'],
  'aws-kms':        ['AWS_KMS_KEY_ID', 'AWS_KMS_REGION', 'AWS_KMS_EDK_PATH'],
  'azure-kv':       ['AZURE_KEY_VAULT_URI', 'AZURE_KEY_VAULT_KEY_NAME', 'AZURE_KEY_VAULT_KEY_VER', 'AZURE_WRAPPED_KEY_PATH'],
  'gcp-kms':        ['GCP_KMS_PROJECT', 'GCP_KMS_KEYRING', 'GCP_KMS_KEY', 'GCP_KMS_LOCATION', 'GCP_KMS_KEY_VERSION', 'GCP_KMS_KEY_TYPE', 'GCP_WRAPPED_KEY_PATH'],
  'hsm':            ['HSM_PKCS11_LIB', 'HSM_PKCS11_SLOT', 'HSM_PKCS11_PIN', 'HSM_PKCS11_PIN_FILE', 'HSM_KEY_INDEX_PATH'],
};

function _buildRaw(provider) {
  return { provider, ..._pick(_FIELDS_BY_PROVIDER[provider] || []) };
}

// ── Public entry point ──────────────────────────────────────────────────────

/**
 * Validate the KMS/Vault configuration surface for the currently-selected
 * (or explicitly given) provider.
 *
 * @param {string} [providerOverride] - defaults to QODIQA_KMS_PROVIDER, then 'local'.
 * @returns {{ provider: string, valid: true, errors: [], data?: object }}
 * @throws {Error} if the provider is recognized but its required fields are
 *   missing or invalid — after emitting a single structured FATAL naming
 *   every offending field.
 */
function validateKmsConfig(providerOverride) {
  const provider = providerOverride || process.env.QODIQA_KMS_PROVIDER || 'local';

  if (!KNOWN_PROVIDERS.includes(provider)) {
    // Unrecognized provider name — left entirely to keyProviderFactory.js's
    // own switch-statement error (see module header comment).
    return { provider, valid: true, errors: [] };
  }

  const raw    = _buildRaw(provider);
  const result = KmsConfigSchema.safeParse(raw);

  if (!result.success) {
    const errors = result.error.issues.map(i => i.message);
    emit('FATAL', 'KMS_CONFIG_INVALID', { provider, errorCount: errors.length, errors });
    throw new Error(`KMS configuration invalid for provider "${provider}": ${errors.join('; ')}`);
  }

  emit('INFO', 'KMS_CONFIG_VALID', { provider });
  return { provider, valid: true, errors: [], data: result.data };
}

module.exports = {
  validateKmsConfig,
  KmsConfigSchema,
  KNOWN_PROVIDERS,
  // Exported for targeted unit testing — underscore prefix signals internal use.
  _buildRaw,
  _FIELDS_BY_PROVIDER,
};
