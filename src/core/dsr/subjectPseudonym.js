'use strict';

/**
 * Per-subject pseudonyms —.
 *
 *   pseudonym   = 'ap1:' + hex HMAC-SHA256(K_subject, tenant ‖ 0x00 ‖ actorId)
 *   subject_ref = hex HMAC-SHA256 under the ledger key, over the domain label (LEDGER_DOMAIN) ‖ 0x00 ‖ tenant ‖ 0x00 ‖ actorId
 *
 * K_subject is 32 random bytes per (tenant, data subject), KEK-encrypted in
 * subject_pseudonym_keys (migration 063, RLS + FORCE, app may SELECT/INSERT).
 * Erasure writes the pseudonym wherever the subject's identifier sits in an
 * erasable table, then qodiqa_erase_subject_finalize DELETES the key: the
 * pseudonym can no longer be linked back to the subject. The value format is
 * also the one receives for audit-chain `consentProvenance.subject` /
 * `callerContext.callerId`.
 *
 * subject_ref keys the append-only erasure ledger that the DR restore hook
 * replays. Its key is derived from
 * QODIQA_DSR_PSEUDONYM_PEPPER (already mandatory in production), domain-
 * separated — erasure never destroys it, so a restored backup can always be
 * matched against the ledger.
 */

const crypto = require('crypto');
const pool = require('../../infra/postgres/pool');
const { encryptKeyMaterial, decryptKeyMaterial } = require('../../../services/artifact/keyEncryption');

const PREFIX = 'ap1:';
const LEDGER_DOMAIN = 'qodiqa-erasure-ledger-v1';

const ST = require('../../observability/stageTimer');
// closure diagnostic (bench only): pool connect() wait, attributed to the caller's request record (S33pw).
const _RUN_OPTS = ST.ON ? { onAcquireWait: (ms) => ST.add('S33pw', ms) } : undefined;

function _run(tenantId, fn) {
  if (_RUN_OPTS) return tenantId ? pool.withTenantTransaction(tenantId, fn, _RUN_OPTS) : pool.withTransaction(fn, _RUN_OPTS);
  return tenantId ? pool.withTenantTransaction(tenantId, fn) : pool.withTransaction(fn);
}

/** Load the subject's key, creating it on first use. PostgreSQL is required. */
async function _subjectKey(tenantId, actorId) {
  if (!pool.isEnabled()) {
    const e = new Error('subject pseudonyms require PostgreSQL (subject_pseudonym_keys)');
    e.code = 'SUBJECT_PSEUDONYM_UNAVAILABLE';
    throw e;
  }
  return _run(tenantId, (tx) => _subjectKeyWithClient(tx, tenantId, actorId));
}

async function _subjectKeyWithClient(tx, tenantId, actorId) {
  const sel = 'SELECT key_enc FROM subject_pseudonym_keys WHERE actor_id = $1 AND tenant_id IS NOT DISTINCT FROM $2';
  let r = await tx.query(sel, [actorId, tenantId ?? null]);
  if (!r.rows.length) {
    const enc = encryptKeyMaterial(crypto.randomBytes(32), { keyId: 'subject-pseudonym' });
    await tx.query(
      `INSERT INTO subject_pseudonym_keys (tenant_id, actor_id, key_enc) VALUES ($1, $2, $3)
       ON CONFLICT (COALESCE(tenant_id, ''), actor_id) DO NOTHING`,
      [tenantId ?? null, actorId, JSON.stringify(enc)],
    );
    r = await tx.query(sel, [actorId, tenantId ?? null]);
  }
  return decryptKeyMaterial(r.rows[0].key_enc);
}

/** pseudonymFor() on a caller-supplied client (DR restore replay, scripts/dr/erasureReplay.js). */
async function pseudonymForWithClient(client, tenantId, actorId) {
  if (isPseudonym(actorId)) return actorId;
  return _pseudonymWithKey(await _subjectKeyWithClient(client, tenantId, actorId), tenantId, actorId);
}

function _pseudonymWithKey(key, tenantId, actorId) {
  return PREFIX + crypto.createHmac('sha256', key).update(`${tenantId ?? ''}\u0000${actorId}`).digest('hex');
}

/**
 * The subject's pseudonym (get-or-create key). An identifier that already is
 * a pseudonym is returned unchanged, so a resumed erasure is idempotent.
 */
async function pseudonymFor(tenantId, actorId) {
  if (!actorId) throw new Error('actorId is required');
  if (isPseudonym(actorId)) return actorId;
  return _pseudonymWithKey(await _subjectKey(tenantId, actorId), tenantId, actorId);
}

function isPseudonym(v) { return typeof v === 'string' && /^ap1:[0-9a-f]{64}$/.test(v); }

function _ledgerKey() {
  const pepper = process.env.QODIQA_DSR_PSEUDONYM_PEPPER || process.env.QODIQA_SIGNING_SECRET;
  if (!pepper) {
    const e = new Error('QODIQA_DSR_PSEUDONYM_PEPPER (or QODIQA_SIGNING_SECRET) must be set to record or replay erasures');
    e.code = 'ERASURE_LEDGER_KEY_MISSING';
    throw e;
  }
  return crypto.createHmac('sha256', pepper).update(LEDGER_DOMAIN).digest();
}

/** Erasure-ledger reference for (tenant, subject): stable, keyed, not reversible without the key. */
function subjectRef(tenantId, actorId) {
  return crypto.createHmac('sha256', _ledgerKey()).update(`${LEDGER_DOMAIN}\u0000${tenantId ?? ''}\u0000${actorId}`).digest('hex');
}

module.exports = { pseudonymFor, pseudonymForWithClient, subjectRef, isPseudonym, PREFIX, _pseudonymWithKey };
