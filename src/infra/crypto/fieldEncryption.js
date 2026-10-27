'use strict';

/**
 * Application-level field encryption: sensitive values in PostgreSQL that are not part of a hash chain (so they can be encrypted without breaking verifiability) are
 * sealed with AES-256-GCM before they are written, under a key derived from the platform's Key Encryption Key.
 *
 *   seal(value, { purpose, aad })        -> 'qfe1.<kid>.<iv>.<ciphertext>.<tag>'   (base64url parts)
 *   open(sealed, { purpose, aad })       -> the value
 *   sealObject(value, ctx) / openObject(stored, ctx)    for a JSONB column that must stay an object: { "$qfe": "<sealed>" }; an object WITHOUT "$qfe" (a row written before
 *                                         encryption was on) is returned as it is, so enabling it needs no data migration
 *   reseal(sealed, ctx, oldKek, newKek)  KEK rotation
 *
 * Key: HKDF-SHA256(KEK, salt "QODIQA::FIELD::V1", info = purpose) -> 32 bytes, so a value sealed for one purpose cannot be opened as another. The KEK comes from
 * services/secrets/secretsProvider (the same provider as the signing keys and webhook secrets - Vault / KMS / HSM / env); a dedicated KEK for this use is picked up from
 * QODIQA_FIELD_KEY_ENCRYPTION_KEY when set (scope "field"). AAD binds the ciphertext to its row (tenant, table, id, column) so a sealed value copied to another row fails to open.
 * `kid` (first 4 bytes of SHA-256 of the KEK) names the key that sealed it, so a wrong or rotated key is reported as such and not as corruption.
 *
 * QODIQA_FIELD_ENCRYPTION: "auto" (default) seals when a KEK is available and, outside production, stores plaintext with a warning when it is not; "required" (and always in
 * production) refuses to store a sensitive field without sealing it; "off" disables sealing (reading sealed values still works).
 */

const crypto = require('crypto');
const secretsProvider = require('../../../services/secrets/secretsProvider');

const PREFIX = 'qfe1';
const SALT = Buffer.from('QODIQA::FIELD::V1', 'utf8');
const IV_BYTES = 12;
const b64 = (b) => Buffer.from(b).toString('base64url');
const unb64 = (s) => Buffer.from(s, 'base64url');

class FieldEncryptionError extends Error { constructor(code, message) { super(message || code); this.name = 'FieldEncryptionError'; this.code = code; } }

function mode(env = process.env) {
  if (env.NODE_ENV === 'production') return env.QODIQA_FIELD_ENCRYPTION === 'off' ? 'off' : 'required';
  const m = env.QODIQA_FIELD_ENCRYPTION;
  return m === 'required' || m === 'off' ? m : 'auto';
}

function currentKek() {
  const k = secretsProvider.getKeyEncryptionKey('field');
  if (!Buffer.isBuffer(k) || k.length !== 32) throw new FieldEncryptionError('FIELD_KEK_INVALID', 'the key encryption key must be 32 bytes');
  return k;
}
const kidOf = (kek) => crypto.createHash('sha256').update(kek).digest().subarray(0, 4).toString('hex');
const subkey = (kek, purpose) => Buffer.from(crypto.hkdfSync('sha256', kek, SALT, Buffer.from(String(purpose), 'utf8'), 32));
const aadOf = (purpose, aad) => Buffer.from(`${purpose}\u0000${aad || ''}`, 'utf8');

function _seal(value, { purpose, aad }, kek) {
  if (typeof purpose !== 'string' || !purpose) throw new FieldEncryptionError('FIELD_PURPOSE_REQUIRED');
  const iv = crypto.randomBytes(IV_BYTES);
  const c = crypto.createCipheriv('aes-256-gcm', subkey(kek, purpose), iv);
  c.setAAD(aadOf(purpose, aad));
  const ct = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
  return [PREFIX, kidOf(kek), b64(iv), b64(ct), b64(c.getAuthTag())].join('.');
}

function _open(sealed, { purpose, aad }, kek) {
  const parts = typeof sealed === 'string' ? sealed.split('.') : [];
  if (parts.length !== 5 || parts[0] !== PREFIX) throw new FieldEncryptionError('FIELD_NOT_SEALED', 'not a sealed field');
  if (parts[1] !== kidOf(kek)) throw new FieldEncryptionError('FIELD_KEY_MISMATCH', `sealed under key ${parts[1]}, the current key is ${kidOf(kek)}`);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', subkey(kek, purpose), unb64(parts[2]));
    d.setAAD(aadOf(purpose, aad)); d.setAuthTag(unb64(parts[4]));
    return JSON.parse(Buffer.concat([d.update(unb64(parts[3])), d.final()]).toString('utf8'));
  } catch (e) {
    if (e instanceof FieldEncryptionError) throw e;
    throw new FieldEncryptionError('FIELD_AUTH_FAILED', 'the sealed field failed authentication (wrong purpose, wrong row, or altered)');
  }
}

const isSealed = (v) => typeof v === 'string' && v.startsWith(`${PREFIX}.`) && v.split('.').length === 5;

function seal(value, ctx) { return _seal(value, ctx, currentKek()); }
function open(sealed, ctx) { return _open(sealed, ctx, currentKek()); }

let _warned = false;
/** For a JSONB column that must remain an object. Honors the mode (see the header). */
/** @param {any} value @param {any} ctx @param {{ emit?: Function }} [opts] */
function sealObject(value, ctx, { emit } = {}) {
  const m = mode();
  if (m === 'off') return value;
  let kek;
  try { kek = currentKek(); } catch (e) {
    if (m === 'required') throw new FieldEncryptionError('FIELD_ENCRYPTION_UNAVAILABLE', `field encryption is required but no key is available: ${e.message}`);
    if (!_warned && emit) { _warned = true; emit('WARN', 'FIELD_ENCRYPTION_UNAVAILABLE', { purpose: ctx.purpose, message: 'no key encryption key: sensitive fields are stored in plaintext (auto mode, not production)' }); }
    return value;
  }
  return { $qfe: _seal(value, ctx, kek) };
}

function openObject(stored, ctx) {
  if (stored && typeof stored === 'object' && !Array.isArray(stored) && typeof stored.$qfe === 'string') return _open(stored.$qfe, ctx, currentKek());
  return stored;                                                        // written before encryption was enabled
}

function reseal(sealed, ctx, oldKek, newKek) { return _seal(_open(sealed, ctx, oldKek), ctx, newKek); }

module.exports = { seal, open, sealObject, openObject, reseal, isSealed, mode, kidOf, FieldEncryptionError, _resetWarnForTests: () => { _warned = false; } };
