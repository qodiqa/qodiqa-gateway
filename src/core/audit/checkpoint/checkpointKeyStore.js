'use strict';

/**
 * QODIQA audit-checkpoint key store — step 6 (design decision M1 = (a), 2026-09-30).
 *
 * A dedicated Ed25519 signing key for signed audit-chain checkpoints, in its OWN encrypted key file — separate from
 * the artifact key store and from the transparency key store (a different trust domain: a checkpoint vouches for a
 * prefix of the audit chain that may later be archived and removed; a transparency key signs log roots).
 *
 *   FILE:        QODIQA_CHECKPOINT_KEYS_PATH, else checkpoint-keys.json NEXT TO QODIQA_TRANSPARENCY_KEYS_PATH, else
 *                data/checkpoint-keys.json
 *   ENCRYPTION:  AES-256-GCM under QODIQA_KEY_ENCRYPTION_KEY (same KEK as the other stores, separate file)
 *   PURPOSE:     'audit-checkpoint'
 *   KEY IDS:     <cp-client>:key_vN — 'cp-' + QODIQA_CLIENT_ID, or QODIQA_CHECKPOINT_KEY_CLIENT, or 'cp-default'
 *   LIFECYCLE:   same as the transparency store (./ed25519KeyStore.js): exactly one active key, 90-day rotation,
 *                180-day expiry, rotateKey() = emergency (revoke) by default, rotateKeyGracefully() keeps the old key
 *                verifiable (deprecated) — old checkpoints stay verifiable only through a graceful rotation.
 *   PUBLIC KEYS: publishedKeys() — every non-revoked public key, for verifiers (the independent verifier and the
 * published key set; : "publish its public key for verifiers"). A KMS move is.
 */

const path = require('path');
const { createEd25519KeyStore } = require('../../transparency/ed25519KeyStore');

function _checkpointClientId() {
  if (process.env.QODIQA_CHECKPOINT_KEY_CLIENT) return process.env.QODIQA_CHECKPOINT_KEY_CLIENT;
  const base = process.env.QODIQA_CLIENT_ID;
  return base ? `cp-${base}` : 'cp-default';
}

const store = createEd25519KeyStore({
  // Default: next to the transparency key file when that is configured (keys live together, outside the repo in
  // production — and every test/tooling spawner that isolates the transparency keys isolates these with it), else
  // data/checkpoint-keys.json.
  dataPath: process.env.QODIQA_CHECKPOINT_KEYS_PATH
    || (process.env.QODIQA_TRANSPARENCY_KEYS_PATH ? path.join(path.dirname(path.resolve(process.env.QODIQA_TRANSPARENCY_KEYS_PATH)), 'checkpoint-keys.json') : null)
    || path.join(__dirname, '..', '..', '..', '..', 'data', 'checkpoint-keys.json'),
  purpose: 'audit-checkpoint',
  resolveClientId: _checkpointClientId,
  storeName: 'CheckpointKeyStore',
  noun: 'checkpoint',
  title: 'Checkpoint',
  eventPrefix: 'CHECKPOINT_KEY',
  storeEvent: 'CHECKPOINT_KEYSTORE_LOADED',
  violationNoun: 'CHECKPOINT',
});

/** Provision the first key if none is active (startup and the checkpoint writer call this). */
function ensureActiveKey() {
  try { return store.getActiveKey(); } catch (e) {
    if (!/no active checkpoint signing key/.test(e.message)) throw e;
    store.rotateKey();
    return store.getActiveKey();
  }
}

/** The public key set verifiers need: every non-revoked key (active + deprecated), SPKI DER base64. */
function publishedKeys() {
  return store.listKeys().filter((k) => k.status !== 'revoked').map((k) => ({
    keyId: k.keyId, algorithm: k.algorithm, purpose: k.purpose, status: k.status, publicKeySpkiDerB64: k.publicKeyB64,
    createdAt: k.createdAt, retiredAt: k.retiredAt, expiresAt: k.expiresAt,
  }));
}

module.exports = {
  getActiveKey: store.getActiveKey,
  getPublicKey: store.getPublicKey,
  getKeyStatus: store.getKeyStatus,
  rotateKey: store.rotateKey,
  rotateKeyGracefully: store.rotateKeyGracefully,
  revokeKey: store.revokeKey,
  validateKeyStore: store.validateKeyStore,
  listKeys: store.listKeys,
  reloadFromDisk: store.reloadFromDisk,               // (driven by keyManager.reload())
  _scanFileForPlaintext: store._scanFileForPlaintext,
  ensureActiveKey,
  publishedKeys,
  _checkpointClientId,
  KEY_PURPOSE: store.KEY_PURPOSE,
  DATA_PATH: store.DATA_PATH,
  _resetStore: store._resetStore,
};
