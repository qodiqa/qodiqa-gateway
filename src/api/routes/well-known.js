'use strict';

const { Router }  = require('express');
const { keyDates } = require('./shared/publicKeyDates');
const { listKeys, getKeyStatus, getPublicKey, listArchivedKeys } = require('../../../services/artifact/keyStore.js');
const {
  listKeys: listTransparencyKeys,
  getKeyStatus: getTransparencyKeyStatus,
  getPublicKey: getTransparencyPublicKey,
} = require('../../core/transparency/transparencyKeyStore.js');
// step 6: the audit-checkpoint signing keys — a third, separate trust domain — published for verifiers.
const {
  listKeys: listCheckpointKeys,
  getKeyStatus: getCheckpointKeyStatus,
  getPublicKey: getCheckpointPublicKey,
} = require('../../core/audit/checkpoint/checkpointKeyStore.js');
const { createRateLimitMiddleware } = require('../../core/rateLimit');

const VERIFIABLE = new Set(['active', 'deprecated']);

// Canonical keyId format: <clientId>:key_v<version>
// Validated before any key store lookup to prevent enumeration via malformed IDs.
const KEY_ID_RE = /^[A-Za-z0-9_-]{1,64}:key_v[0-9]+$/;

// Rate limit for public key-discovery endpoints: 120 requests / 60 seconds.
// Prevents automated enumeration of key material.
const keysRateLimit = createRateLimitMiddleware('well_known', { envelope: 'decision' });

// independent, stricter limiter for the archived-key discovery
// endpoint below — see the 'well_known_archived' surface in
// src/core/rateLimit/config.js for the rationale and default budget.
const archivedKeysRateLimit = createRateLimitMiddleware('well_known_archived', { envelope: 'decision' });

const router = Router();

// GET /.well-known/qodiqa/keys
// Returns all non-revoked keys eligible for artifact verification.
// createdAt is omitted — it is internal lifecycle metadata and its exposure
// would allow timing-based correlation of key rotation events.
router.get('/qodiqa/keys', keysRateLimit, (req, res) => {
  const keys = listKeys()
    .filter(k => VERIFIABLE.has(k.status))
    .map(k => ({
      keyId:     k.keyId,
      algorithm: 'ed25519',
      publicKey: k.publicKeyB64,
      status:    k.status,
      ...keyDates(k),
    }));

  return res.status(200).json({ keys, requestId: req.requestId ?? null });
});

router.use('/qodiqa/keys', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/keys/archived
//
// Returns archived (purged, formerly-'deprecated') artifact-signing keys —
// the discovery-endpoint counterpart to getPublicKey()'s archive fallback in
// services/artifact/keyStore.js. Exists so verifiers (including the SDKs'
// RemoteKeyProvider) can resolve a keyId that no longer appears in the live
// /qodiqa/keys list without needing any out-of-band access to
// data/key-archive.json.
//
// MUST be registered before the '/qodiqa/keys/:keyId' route below — Express
// matches routes in registration order, and 'archived' would otherwise be
// consumed as a (non-matching, 404-producing) :keyId value first, so a
// request would never reach this handler.
//
// Read-only, public material only, no mutation: listArchivedKeys() only ever
// returns publicKeyB64 — the archive never contains private key material in
// the first place (stripped at rotation time, long before a key is ever
// purge-eligible). Status is always 'archived' here; unlike the live
// endpoint's active/deprecated distinction, every entry in the archive is
// equally "purged and no longer live" — 'source' is included as an explicit,
// redundant marker for observability, matching the live/archived 'source'
// field getPublicKey() attaches internally.
router.get('/qodiqa/keys/archived', archivedKeysRateLimit, (req, res) => {
  let entries;
  try {
    entries = listArchivedKeys();
  } catch {
    return res.status(500).json({ decision: 'BLOCK', reason: 'KEY_ARCHIVE_UNAVAILABLE', details: {}, requestId: req.requestId ?? null });
  }

  const keys = entries.map(e => ({
    keyId:     e.keyId,
    algorithm: 'ed25519',
    publicKey: e.publicKeyB64,
    status:    'archived',
    source:    'archived',
  }));

  return res.status(200).json({ keys, requestId: req.requestId ?? null });
});

router.use('/qodiqa/keys/archived', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/keys/:keyId
// Returns a single verifiable key by canonical ID.
// keyId format is validated before any lookup to prevent enumeration via
// malformed identifiers that could produce different error shapes.
router.get('/qodiqa/keys/:keyId', keysRateLimit, (req, res) => {
  const { keyId } = req.params;
  const reqId     = req.requestId ?? null;

  if (!KEY_ID_RE.test(keyId)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  const status = getKeyStatus(keyId);
  if (status === null || !VERIFIABLE.has(status)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  let pubDer;
  try {
    ({ pubDer } = getPublicKey(keyId));
  } catch {
    return res.status(500).json({ decision: 'BLOCK', reason: 'KEY_UNAVAILABLE', details: {}, requestId: reqId });
  }

  return res.status(200).json({
    keyId,
    algorithm: 'ed25519',
    publicKey: pubDer.toString('base64'),
    status,
    requestId: reqId,
  });
});

router.use('/qodiqa/keys/:keyId', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/transparency-keys
// Returns all non-revoked transparency-log signing keys (a completely
// separate trust domain from the artifact-signing keys above — see
// src/core/transparency/transparencyKeyStore.js's cryptographic-separation
// note). Needed so SDKs can locally verify Merkle inclusion-proof entry/root
// signatures without trusting the server's own verdict.
// createdAt is omitted for the same rotation-timing-correlation reason as
// the artifact keys route above.
router.get('/qodiqa/transparency-keys', keysRateLimit, (req, res) => {
  const keys = listTransparencyKeys()
    .filter(k => VERIFIABLE.has(k.status))
    .map(k => ({
      keyId:     k.keyId,
      algorithm: 'ed25519',
      publicKey: k.publicKeyB64,
      status:    k.status,
      ...keyDates(k),
    }));

  return res.status(200).json({ keys, requestId: req.requestId ?? null });
});

router.use('/qodiqa/transparency-keys', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/transparency-keys/:keyId
// Returns a single verifiable transparency key by canonical ID. Same
// enumeration-resistance properties as /qodiqa/keys/:keyId: keyId format is
// validated before any store lookup, and malformed/unknown/revoked all
// produce the identical 404 shape.
router.get('/qodiqa/transparency-keys/:keyId', keysRateLimit, (req, res) => {
  const { keyId } = req.params;
  const reqId     = req.requestId ?? null;

  if (!KEY_ID_RE.test(keyId)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  const status = getTransparencyKeyStatus(keyId);
  if (status === null || !VERIFIABLE.has(status)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  let pubDer;
  try {
    ({ pubDer } = getTransparencyPublicKey(keyId));
  } catch {
    return res.status(500).json({ decision: 'BLOCK', reason: 'KEY_UNAVAILABLE', details: {}, requestId: reqId });
  }

  return res.status(200).json({
    keyId,
    algorithm: 'ed25519',
    publicKey: pubDer.toString('base64'),
    status,
    requestId: reqId,
  });
});

router.use('/qodiqa/transparency-keys/:keyId', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/checkpoint-keys
// step 6: every non-revoked audit-CHECKPOINT signing key (src/core/audit/checkpoint/checkpointKeyStore.js),
// so an independent verifier can check a signed checkpoint (and audit.log.base.json after an archived prefix was
// removed) without trusting this server. Same shape, rate limit and enumeration resistance as the transparency keys.
router.get('/qodiqa/checkpoint-keys', keysRateLimit, (req, res) => {
  const keys = listCheckpointKeys()
    .filter(k => VERIFIABLE.has(k.status))
    .map(k => ({
      keyId:     k.keyId,
      algorithm: 'ed25519',
      publicKey: k.publicKeyB64,
      status:    k.status,
    }));

  return res.status(200).json({ keys, requestId: req.requestId ?? null });
});

router.use('/qodiqa/checkpoint-keys', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

// GET /.well-known/qodiqa/checkpoint-keys/:keyId — one verifiable checkpoint key; malformed, unknown and revoked ids
// all produce the identical 404 (as the transparency-keys route).
router.get('/qodiqa/checkpoint-keys/:keyId', keysRateLimit, (req, res) => {
  const { keyId } = req.params;
  const reqId     = req.requestId ?? null;

  if (!KEY_ID_RE.test(keyId)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  const status = getCheckpointKeyStatus(keyId);
  if (status === null || !VERIFIABLE.has(status)) {
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
  }

  let pubDer;
  try {
    ({ pubDer } = getCheckpointPublicKey(keyId));
  } catch {
    return res.status(500).json({ decision: 'BLOCK', reason: 'KEY_UNAVAILABLE', details: {}, requestId: reqId });
  }

  return res.status(200).json({ keyId, algorithm: 'ed25519', publicKey: pubDer.toString('base64'), status, requestId: reqId });
});

router.use('/qodiqa/checkpoint-keys/:keyId', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null });
  }
  next();
});

module.exports = router;
