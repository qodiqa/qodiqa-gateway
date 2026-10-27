'use strict';

/**
 * QODIQA Transparency Key Store — Component #30
 *
 * Independent Ed25519 key management for transparency signing.
 * Completely separate from the artifact key store (services/artifact/keyStore.js).
 *
 * CRYPTOGRAPHIC SEPARATION:
 *   This store knows nothing about artifact keys.
 *   The artifact key store knows nothing about transparency keys.
 *   No code path can return a transparency key for artifact signing or vice versa.
 *   Compromise of either key set cannot compromise the other trust domain.
 *
 * KEY FORMAT:   <transparencyClientId>:key_vN
 * FILE PATH:    data/transparency-keys.json  (env: QODIQA_TRANSPARENCY_KEYS_PATH)
 * ENCRYPTION:   AES-256-GCM via QODIQA_KEY_ENCRYPTION_KEY (same KEK, separate file)
 * PURPOSE TAG:  Every record carries purpose: 'transparency' — never 'artifact'
 *
 * LIFECYCLE:  active → deprecated → revoked
 * INVARIANT:  exactly one active transparency key at any time
 *
 * HISTORICAL VERIFICATION:
 *   Deprecated (retired) keys remain in-store indefinitely.
 *   getPublicKey(keyId) succeeds for deprecated keys.
 *   Old transparency roots remain verifiable indefinitely post-rotation —
 *   but ONLY when rotation was explicitly performed via rotateKeyGracefully().
 *
 * remediation (mirrors services/artifact/keyStore.js):
 *   rotateKey() DEFAULTS to 'graceful' mode since audit 2026-10-20 (3.10); it used to default to 'emergency' mode — the outgoing key is REVOKED,
 *   not deprecated, immediately losing both signing and verification
 *   capability. rotateKeyGracefully() is the separate, explicit entry point for
 *   planned migration that preserves the old deprecate-and-keep-verifiable behavior.
 *
 * loading is lazy (first use), never a require()-time side effect.
 *
 * step 6 (design decision M1 = (a)): the implementation now lives in ./ed25519KeyStore.js
 * (createEd25519KeyStore), shared with the separate audit-checkpoint key store
 * (src/core/audit/checkpoint/checkpointKeyStore.js). This module is the transparency instance: same exports,
 * same file (path resolved at load), same purpose tag, key ids, event names and error texts as before.
 */

const path = require('path');
const { createEd25519KeyStore } = require('./ed25519KeyStore');

/**
 * Resolve the transparency signing client ID.
 *
 * Priority:
 *   1. QODIQA_TRANSPARENCY_KEY_CLIENT — explicit override
 *   2. 'tr-' + QODIQA_CLIENT_ID      — derived from artifact client, different namespace
 *   3. 'tr-default'                   — safe fallback for dev / tests
 *
 * The 'tr-' prefix ensures transparency keyIds ('tr-myapp:key_v1') are structurally
 * distinct from artifact keyIds ('myapp:key_v1') — cross-store confusion is impossible.
 */
function _transparencyClientId() {
  if (process.env.QODIQA_TRANSPARENCY_KEY_CLIENT) {
    return process.env.QODIQA_TRANSPARENCY_KEY_CLIENT;
  }
  const base = process.env.QODIQA_CLIENT_ID;
  return base ? `tr-${base}` : 'tr-default';
}

const store = createEd25519KeyStore({
  dataPath: process.env.QODIQA_TRANSPARENCY_KEYS_PATH
    || path.join(__dirname, '..', '..', '..', 'data', 'transparency-keys.json'),
  purpose: 'transparency',
  resolveClientId: _transparencyClientId,
  storeName: 'TransparencyKeyStore',
  noun: 'transparency',
  title: 'Transparency',
  eventPrefix: 'TRANSPARENCY_KEY',
  storeEvent: 'TRANSPARENCY_KEYSTORE_LOADED',
  violationNoun: 'TRANSPARENCY',
  // a routine rotation must not make everything the outgoing key signed unverifiable. 'emergency'
  // (revoke = compromise response) is still available, but only when asked for explicitly.
  defaultRotationMode: 'graceful',
});

module.exports = {
  getActiveKey:        store.getActiveKey,
  getPublicKey:        store.getPublicKey,
  getKeyStatus:        store.getKeyStatus,
  rotateKey:           store.rotateKey,
  rotateKeyGracefully: store.rotateKeyGracefully,
  revokeKey:           store.revokeKey,
  validateKeyStore:    store.validateKeyStore,
  listKeys:            store.listKeys,
  // cross-instance reload (driven by keyManager.reload()) + plaintext scan
  reloadFromDisk:      store.reloadFromDisk,
  _scanFileForPlaintext: store._scanFileForPlaintext,
  DATA_PATH:           store.DATA_PATH,
  _transparencyClientId,
  // Lifecycle constants (mirror artifact key store for tooling parity)
  ROTATION_DAYS:       store.ROTATION_DAYS,
  EXPIRY_DAYS:         store.EXPIRY_DAYS,
  EXPIRY_WARNING_DAYS: store.EXPIRY_WARNING_DAYS,
  KEY_PURPOSE:         store.KEY_PURPOSE,
  // Test-only — do not use in production code
  _resetStore:         store._resetStore,
};
