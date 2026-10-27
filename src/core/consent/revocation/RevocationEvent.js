'use strict';

/**
 * RevocationEvent — canonical event format for instant consent revocation.
 *
 * Events are published to the Redis pub/sub channel and received by all
 * subscriber nodes in a QODIQA cluster.  Each event is:
 *   - Versioned (for forward compatibility)
 * - MAC-signed, always: the shared keystore MAC keyring
 *     (src/core/security/macKeyring.js), over EVERY field (v2 adds revokedBy
 *     and revocationReason to the signed form — NF-5)
 *   - Replay-protected (timestamp window via REVOCATION_MAX_EVENT_AGE_MS)
 *   - Deduplicated by eventId (UUID) in the subscriber
 *
 * An unsigned message, a bad or unknown-key signature, and any v1 message are
 * rejected (counted in qodiqa_pubsub_signature_rejects_total and logged by the
 * subscriber). REVOCATION_SIGNING_KEY is no longer read.
 */

const { randomUUID } = require('crypto');
// signatures come from the shared keystore MAC keyring and are
// MANDATORY in every profile. v1 (optional HMAC under REVOCATION_SIGNING_KEY,
// accepted unsigned when the key was unset) is no longer accepted.
const macKeyring = require('../../security/macKeyring');

const EVENT_VERSION    = '2';
const CHANNEL          = 'qodiqa:consent:revocation';
const MAX_EVENT_AGE_MS = parseInt(process.env.REVOCATION_MAX_EVENT_AGE_MS || '30000', 10);

/**
 * Build a deterministic signing payload from an event object.
 * Only canonical fields are included; order is fixed to ensure
 * consistent HMAC across serialization contexts.
 */
function _canonicalize(event) {
  return JSON.stringify({
    eventId:             event.eventId,
    version:             event.version,
    consentId:           event.consentId    ?? null,
    subjectId:           event.subjectId,
    action:              event.action       ?? null,
    tenantId:            event.tenantId     ?? null,
    // consentVersion drives the CAS guard in ConsentCache on the
    // receiving node (see RevocationSubscriber._handleMessage) — it must be
    // part of the signed payload, otherwise an on-path attacker able to
    // tamper with an unsigned field could downgrade it to make a stale
    // tombstone lose the CAS check and let a resurrected ALLOW entry stand.
    consentVersion:      event.consentVersion ?? null,
    revocationTimestamp: event.revocationTimestamp,
    correlationId:       event.correlationId ?? null,
    sourceSystem:        event.sourceSystem,
    // (NF-5): v1 left these two out of the signed form, so an on-path
    // writer could rewrite who revoked and why without breaking the MAC.
    revokedBy:           event.revokedBy        ?? null,
    revocationReason:    event.revocationReason ?? null,
  });
}

function _sign(event) {
  return macKeyring.sign(macKeyring.PURPOSES.REVOCATION, _canonicalize(event));
}

/** @returns {{ ok: boolean, reason?: string }} */
function _verify(event) {
  if (!event.signature) return { ok: false, reason: 'MISSING_SIGNATURE' };
  try {
    const v = macKeyring.verify(macKeyring.PURPOSES.REVOCATION, _canonicalize(event), event.signature);
    return v.ok ? { ok: true } : { ok: false, reason: `INVALID_SIGNATURE:${/** @type {any} */ (v).reason}` };
  } catch (e) {
    return { ok: false, reason: 'SIGNATURE_UNVERIFIABLE' }; // keyring unavailable: fail closed
  }
}

function _countReject(reason) {
  try { require('../../../observability/metrics').pubsubSignatureRejectsTotal.inc({ channel: CHANNEL, reason }); } catch { /* metrics never throw */ }
}

/**
 * Build a canonical revocation event envelope.
 *
 * @param {object} opts
 * @param {string|null} [opts.consentId]         - specific consent record UUID (null for actor-level)
 * @param {string}      opts.subjectId         - actor_id being revoked
 * @param {string|null} [opts.action]            - specific action (null for actor-level revocation)
 * @param {string|null} [opts.tenantId]
 * @param {string|null} [opts.revokedBy]
 * @param {string|null} [opts.revocationReason]
 * @param {string|null} [opts.correlationId]     - request_id for audit correlation
 * @param {number|null} [opts.consentVersion]  - consent_records.version after this mutation;
 * propagated so receiving nodes can CAS-guard their cache tombstone
 * @returns {object} signed revocation event envelope
 */
function buildEvent({ consentId = null, subjectId, action = null, tenantId = null,
                      revokedBy = null, revocationReason = null, correlationId = null,
                      consentVersion = null }) {
  const base = {
    eventId:             randomUUID(),
    version:             EVENT_VERSION,
    consentId:           consentId    ?? null,
    subjectId,
    action:              action       ?? null,
    tenantId:            tenantId     ?? null,
    revokedBy:           revokedBy    ?? null,
    revocationReason:    revocationReason ?? null,
    consentVersion:      typeof consentVersion === 'number' && Number.isFinite(consentVersion) ? consentVersion : null,
    revocationTimestamp: new Date().toISOString(),
    correlationId:       correlationId ?? null,
    sourceSystem:        'qodiqa-consent-registry',
  };
  return { ...base, signature: _sign(base) };
}

/**
 * Parse and validate a raw JSON string received from the pub/sub channel.
 *
 * Validation checks (in order):
 *   1. Valid JSON
 *   2. Object (not array)
 *   3. Version matches EVENT_VERSION
 *   4. Required fields present (eventId, subjectId, revocationTimestamp)
 *   5. Timestamp within MAX_EVENT_AGE_MS window (replay protection)
 * 6. Signature valid — mandatory keyring MAC
 *
 * @param {string} raw — raw JSON string from Redis pub/sub
 * @returns {{ ok: true, event: object } | { ok: false, reason: string }}
 */
function parseEvent(raw) {
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    return { ok: false, reason: 'INVALID_JSON' };
  }

  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return { ok: false, reason: 'NOT_OBJECT' };
  }
  if (event.version !== EVENT_VERSION) {
    _countReject('VERSION_MISMATCH');
    return { ok: false, reason: 'VERSION_MISMATCH' };
  }
  if (!event.eventId || typeof event.eventId !== 'string') {
    return { ok: false, reason: 'MISSING_EVENT_ID' };
  }
  if (!event.subjectId || typeof event.subjectId !== 'string') {
    return { ok: false, reason: 'MISSING_SUBJECT_ID' };
  }
  if (!event.revocationTimestamp) {
    return { ok: false, reason: 'MISSING_TIMESTAMP' };
  }

  const ts = new Date(event.revocationTimestamp).getTime();
  if (isNaN(ts) || Date.now() - ts > MAX_EVENT_AGE_MS) {
    return { ok: false, reason: 'EVENT_EXPIRED' };
  }

  const sig = _verify(event);
  if (!sig.ok) {
    _countReject(sig.reason);
    return { ok: false, reason: sig.reason };
  }

  return { ok: true, event };
}

module.exports = { CHANNEL, EVENT_VERSION, buildEvent, parseEvent };
