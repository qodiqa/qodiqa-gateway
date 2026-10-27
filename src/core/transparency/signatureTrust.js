'use strict';

/**
 * Transparency signature trust — ONE implementation of "is this transparency record signed under a verifiable
 * transparency key". Used by the background root audit (scanner/GapScanner.js, ST23-03 /)
 * and by the public GET /transparency/consistency (ST23-07 /) and GET /transparency/proof (ST23-04 /)
 * routes, so the key policy and the checks cannot drift between them.
 *
 * Policy (unchanged, the existing transparency-key lifecycle rule — well-known.js VERIFIABLE, generator.js
 * transparencyLog.js ST23-01/02): a signature counts only under a TRANSPARENCY-store key (never the artifact store)
 * whose status is 'active' or 'deprecated' (deprecated keys keep historical records verifiable; a revoked key only in the explicit timed mode, see below). An unknown or
 * revoked key, a missing signature or signer key id, an unusable key store, or a signature that does not verify
 * never counts as authenticated. The Ed25519 verification itself is log.verifyRootSignature / verifyEntrySignature.
 *
 * Unknown-key reload: only when the caller passes a per-pass context (keyCtx) — the root audit does (design decision
 * D-c: ONE fail-closed transparencyKeyStore.reloadFromDisk() per scan pass, then one re-check). The request paths do
 * not reload (same as /verify; replica staleness after rotation is open design decision R-7).
 *
 * Never throws. Returns only fixed codes and the key status — no key material or signature bytes.
 */

const log = require('./log');

const VERIFIABLE_TRANSPARENCY_KEY_STATUSES = Object.freeze(new Set(['active', 'deprecated']));

// Fixed reason codes, shared with the ST23-01/02 /verify SIGNATURE check vocabulary.
const CODES = Object.freeze({
  signature_missing:     'SIGNATURE_MISSING',
  signer_key_missing:    'SIGNER_KEY_ID_MISSING',
  key_unknown:           'UNKNOWN_KEY',
  key_not_verifiable:    'KEY_NOT_VERIFIABLE',
  key_store_unavailable: 'KEY_STORE_UNAVAILABLE',
  signature_invalid:     'SIGNATURE_INVALID',
});

// Required lazily: requiring the store is side-effect-free, but its bootstrap runs on the first lookup.
const _defaultKeys = () => require('./transparencyKeyStore');

function _status(keys, keyId) {
  try { return { status: keys.getKeyStatus(keyId) }; } catch (err) { return { error: err.message }; }
}

/**
 * @param {'root'|'entry'} kind
 * @param {object} record   DB row (snake_case) or camelCase record carrying signature + signer key id
 * @param {object} [opts]
 * @param {{getKeyStatus:Function,getPublicKey:Function,reloadFromDisk?:Function}|null} [opts.keys]
 *        key-store adapter (default: transparencyKeyStore)
 * @param {{reloadAttempted:boolean}|null} [opts.keyCtx]  per-pass context enabling ONE unknown-key reload
 * @param {Function|null} [opts.onReload]  called with { keyId, reloaded, error } after a reload attempt
 * @returns {{ ok: true, keyStatus: string }
 *         | { ok: false, unavailable: boolean, context: string, code: string, keyStatus?: string|null, reason?: string }}
 */
function checkSignatureTrust(kind, record, { keys = null, keyCtx = null, onReload = null, trustedAt = null } = {}) {
  const fail = (ctx, extra = {}) => ({ ok: false, unavailable: ctx === 'key_store_unavailable', context: `${kind}_${ctx}`, code: CODES[ctx], ...extra });
  const signature = record ? (record.signature ?? null) : null;
  const keyId = record ? (record.signer_key_id ?? record.signerKeyId ?? null) : null;
  if (!signature) return fail('signature_missing');
  if (typeof keyId !== 'string' || keyId === '') return fail('signer_key_missing');

  let store;
  try { store = keys || _defaultKeys(); } catch (err) { return fail('key_store_unavailable', { reason: err.message }); }

  let lookup = _status(store, keyId);
  if (lookup.error) return fail('key_store_unavailable', { reason: lookup.error });

  if (lookup.status == null && keyCtx && !keyCtx.reloadAttempted && typeof store.reloadFromDisk === 'function') {
    keyCtx.reloadAttempted = true;
    let reload;
    try { reload = store.reloadFromDisk(); } catch (err) { reload = { reloaded: false, error: err.message }; }
    if (onReload) onReload({ keyId, reloaded: !!(reload && reload.reloaded), error: (reload && reload.error) || null });
    lookup = _status(store, keyId);
    if (lookup.error) return fail('key_store_unavailable', { reason: lookup.error });
  }
  if (lookup.status == null) return fail('key_unknown');
  // a REVOKED key counts only in the explicit timed mode (the caller supplies `trustedAt`, a time from an authority independent of the
  // record) and only for a trustedAt before the key's revokedAt. Default (no trustedAt): revoked is not verifiable, as before.
  const timed = lookup.status === 'revoked' && trustedAt != null;
  if (!VERIFIABLE_TRANSPARENCY_KEY_STATUSES.has(lookup.status) && !timed) return fail('key_not_verifiable', { keyStatus: lookup.status });

  let pubDer;
  try { pubDer = (timed ? store.getPublicKey(keyId, { trustedAt }) : store.getPublicKey(keyId))?.pubDer; } catch (err) {
    if (timed) return fail('key_not_verifiable', { keyStatus: lookup.status, reason: 'revoked before the trusted time' });
    return fail('key_store_unavailable', { keyStatus: lookup.status, reason: err.message });
  }
  if (!Buffer.isBuffer(pubDer)) return fail('key_store_unavailable', { keyStatus: lookup.status, reason: 'no public key returned' });

  const verified = kind === 'root' ? log.verifyRootSignature(record, pubDer) : log.verifyEntrySignature(record, pubDer);
  return verified ? { ok: true, keyStatus: lookup.status, ...(timed ? { timedRevocation: true } : {}) } : fail('signature_invalid', { keyStatus: lookup.status });
}

module.exports = { checkSignatureTrust, VERIFIABLE_TRANSPARENCY_KEY_STATUSES, CODES };
