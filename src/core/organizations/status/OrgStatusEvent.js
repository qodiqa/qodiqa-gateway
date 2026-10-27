'use strict';

/**
 * OrgStatusEvent — canonical event format for bounded organization-suspension
 * propagation.
 *
 * Events are published to the Redis pub/sub channel and received by every
 * worker/instance in a QODIQA cluster. Each event is:
 *   - Versioned (for forward compatibility)
 * - MAC-signed, always: the shared keystore MAC keyring
 *     (src/core/security/macKeyring.js); unsigned / invalid / v1 messages are
 *     rejected and counted. ORG_STATUS_SIGNING_KEY is no longer read.
 *   - Replay-protected (timestamp window via ORG_STATUS_MAX_EVENT_AGE_MS)
 *   - Carries a monotonic `updatedAt` epoch-ms used by receivers to resolve
 *     out-of-order delivery (an older event can never overwrite a newer one)
 *
 * This mirrors src/core/consent/revocation/RevocationEvent.js — the proven
 * pattern already used in this codebase for instant, fail-closed consent
 * revocation propagation.
 */

const { randomUUID } = require('crypto');
const macKeyring = require('../../security/macKeyring');

const EVENT_VERSION    = '2';
const CHANNEL          = 'qodiqa:org:status:change';
const MAX_EVENT_AGE_MS = parseInt(process.env.ORG_STATUS_MAX_EVENT_AGE_MS || '30000', 10);

function _canonicalize(event) {
  return JSON.stringify({
    eventId:         event.eventId,
    version:         event.version,
    organizationId:  event.organizationId,
    status:          event.status,
    updatedAt:       event.updatedAt,
    updatedBy:       event.updatedBy ?? null,
    correlationId:   event.correlationId ?? null,
    sourceSystem:    event.sourceSystem,
  });
}

function _sign(event) {
  return macKeyring.sign(macKeyring.PURPOSES.ORG_STATUS, _canonicalize(event));
}

/** @returns {{ ok: boolean, reason?: string }} */
function _verify(event) {
  if (!event.signature) return { ok: false, reason: 'MISSING_SIGNATURE' };
  try {
    const v = macKeyring.verify(macKeyring.PURPOSES.ORG_STATUS, _canonicalize(event), event.signature);
    return v.ok ? { ok: true } : { ok: false, reason: `INVALID_SIGNATURE:${/** @type {any} */ (v).reason}` };
  } catch {
    return { ok: false, reason: 'SIGNATURE_UNVERIFIABLE' }; // keyring unavailable: fail closed
  }
}

function _countReject(channel, reason) {
  try { require('../../../observability/metrics').pubsubSignatureRejectsTotal.inc({ channel, reason }); } catch { /* metrics never throw */ }
}

// ── (NF-4): signed values for the authoritative qodiqa:org:status hash ────
// The reconcile sweep used to apply whatever JSON sat in that hash. Each value
// is now { record, m } with m = MAC over "<organizationId>\n<JSON record>",
// binding the record to its field; an unsigned or tampered value is ignored.
const RECORD_HASH = 'qodiqa:org:status';
function sealRecord(organizationId, record) {
  const r = JSON.stringify(record);
  return JSON.stringify({ r, m: macKeyring.sign(macKeyring.PURPOSES.ORG_STATUS_RECORD, `${organizationId}\n${r}`) });
}
/** @returns {object|null} the verified record, or null */
function openRecord(organizationId, raw) {
  let outer;
  try { outer = JSON.parse(raw); } catch { _countReject(RECORD_HASH, 'MALFORMED'); return null; }
  if (!outer || typeof outer.r !== 'string') { _countReject(RECORD_HASH, 'UNSIGNED'); return null; }
  let v;
  try { v = macKeyring.verify(macKeyring.PURPOSES.ORG_STATUS_RECORD, `${organizationId}\n${outer.r}`, outer.m); } catch { v = { ok: false, reason: 'SIGNATURE_UNVERIFIABLE' }; }
  if (!v.ok) { _countReject(RECORD_HASH, /** @type {any} */ (v).reason); return null; }
  try { return JSON.parse(outer.r); } catch { _countReject(RECORD_HASH, 'MALFORMED'); return null; }
}

/**
 * Build a canonical organization status-change event envelope.
 *
 * @param {object} opts
 * @param {string} opts.organizationId
 * @param {string} opts.status         — 'active' | 'suspended' | 'disabled'
 * @param {number} [opts.updatedAt]    - epoch ms; defaults to Date.now()
 * @param {string|null} [opts.updatedBy]
 * @param {string|null} [opts.correlationId]
 * @returns {object} signed event envelope
 */
function buildEvent({ organizationId, status, updatedAt = Date.now(), updatedBy = null, correlationId = null }) {
  const base = {
    eventId:        randomUUID(),
    version:        EVENT_VERSION,
    organizationId,
    status,
    updatedAt,
    updatedBy:      updatedBy ?? null,
    correlationId:  correlationId ?? null,
    sourceSystem:   'qodiqa-organization-registry',
  };
  return { ...base, signature: _sign(base) };
}

/**
 * Parse and validate a raw JSON string received from the pub/sub channel.
 *
 * @param {string} raw
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
    _countReject(CHANNEL, 'VERSION_MISMATCH');
    return { ok: false, reason: 'VERSION_MISMATCH' };
  }
  if (!event.eventId || typeof event.eventId !== 'string') {
    return { ok: false, reason: 'MISSING_EVENT_ID' };
  }
  if (!event.organizationId || typeof event.organizationId !== 'string') {
    return { ok: false, reason: 'MISSING_ORGANIZATION_ID' };
  }
  if (!event.status || typeof event.status !== 'string') {
    return { ok: false, reason: 'MISSING_STATUS' };
  }
  if (typeof event.updatedAt !== 'number' || !Number.isFinite(event.updatedAt)) {
    return { ok: false, reason: 'MISSING_TIMESTAMP' };
  }

  if (Date.now() - event.updatedAt > MAX_EVENT_AGE_MS) {
    return { ok: false, reason: 'EVENT_EXPIRED' };
  }

  const sig = _verify(event);
  if (!sig.ok) {
    _countReject(CHANNEL, sig.reason);
    return { ok: false, reason: sig.reason };
  }

  return { ok: true, event };
}

module.exports = { CHANNEL, EVENT_VERSION, MAX_EVENT_AGE_MS, buildEvent, parseEvent, sealRecord, openRecord };
