'use strict';

/**
 * Signing-key status timeline —.
 *
 * The key MATERIAL stays in the keystore. The STATUS
 * timeline of every key (active → deprecated → archived; any → revoked) is
 * control-plane state, one record per keyId in control_plane_records
 * (store 'signing_key_status'), forward-only in the database as well.
 *
 * Why it exists: keys.json is re-read by other replicas only every 5 min
 *so a key rotated or revoked on one replica kept verifying — and
 * signing — elsewhere. Now:
 *   - every keystore save reconciles this replica's local statuses INTO the
 *     timeline (forward-only, versioned);
 *   - verification uses effective(): the more advanced of the local view and
 *     the timeline, so a rotation/revocation anywhere holds everywhere within
 *     the 5 s control-plane bound;
 *   - signing refuses a key whose effective status is no longer 'active' and
 *     reloads the keystore first (src/core/signing/... keyManager.getSigningKey).
 *
 * In dev/test memory mode there is one process, so effective() is the local
 * view; the collection still records transitions (tests read it).
 */

const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { mergeTimelines, RANK } = require('../../validation/keyLifecycle');
const { emit } = require('../../../services/logger');

const _col = new Collection('signing_key_status', { seed: () => ({}) });

function _keyStore() { return require('../../../services/artifact/keyStore'); }

/** The timeline record for keyId, or null. pg: freshness-checked (CONTROL_PLANE_STALE when stale). */
function get(keyId) { return _col.get(keyId); }

/**
 * The effective timeline for verification/signing: local keystore view merged
 * (forward-only) with the control-plane record.
 */
function effective(keyId, localTimeline) {
  if (!cp.isPg()) return localTimeline || null;
  return mergeTimelines(localTimeline || null, _col.get(keyId));
}

/** Record one key's status (forward-only). Returns synchronously (memory) or a Promise (pg). */
function record({ keyId, clientId, version = null, status, activatedAt = null, deprecatedAt = null, archivedAt = null, revokedAt = null, at = new Date().toISOString() }) {
  const cur = _col.rawValues().find((r) => r.keyId === keyId) || null;
  const next = mergeTimelines(cur, {
    status,
    activatedAt: activatedAt || (status === 'active' ? at : null),
    deprecatedAt: deprecatedAt || (status === 'deprecated' ? at : null),
    archivedAt: archivedAt || (status === 'archived' ? at : null),
    revokedAt: revokedAt || (status === 'revoked' ? at : null),
  });
  const rec = Object.freeze({ keyId, clientId, version, ...next });
  if (cur && JSON.stringify({ ...cur }) === JSON.stringify({ ...cur, ...rec })) return cur; // nothing new
  if (cur && (RANK[cur.status] ?? -1) > (RANK[rec.status] ?? -1)) return cur;            // never backwards
  return _col.put(keyId, rec, { create: !cur, updatedBy: 'keystore' });
}

/**
 * Reconcile every key the local keystore knows (live + archive) into the
 * timeline. Idempotent; conflicts (another replica wrote first) are resolved by
 * the next pull. Returns a Promise in both modes.
 */
async function reconcileAll() {
  const ks = _keyStore();
  const now = new Date().toISOString();
  const jobs = [];
  for (const k of ks.listKeyTimelines()) {
    const t = k.timeline;
    jobs.push({
      keyId: k.keyId, clientId: k.clientId, version: k.version ?? null, status: t.status,
      activatedAt: t.activatedAt,
      // a deprecated key without a recorded retirement is stamped now — the
      // earliest moment this replica can vouch for (fail-closed: shortens its window)
      deprecatedAt: t.status === 'deprecated' ? (t.deprecatedAt || now) : null,
      revokedAt: t.status === 'revoked' ? now : null,
    });
  }
  try {
    for (const a of ks.listArchivedKeys()) {
      jobs.push({ keyId: a.keyId, clientId: a.clientId, status: 'archived', archivedAt: a.purgedAt || now });
    }
  } catch { /* no archive */ }
  let written = 0;
  for (const j of jobs) {
    try {
      const r = record(j);
      if (r && typeof r.then === 'function') { await r; written++; }
    } catch (err) {
      if (err && err.code === 'CONTROL_PLANE_VERSION_CONFLICT') continue;
      emit('WARN', 'KEY_STATUS_TIMELINE_RECORD_FAILED', { keyId: j.keyId, status: j.status, error: err.message, code: err.code ?? null });
      if (cp.isPg()) throw err;
    }
  }
  return { keys: jobs.length, written };
}

/** @type {Promise<any>} */
let _pending = Promise.resolve();
/** Serialised, fire-and-forget reconcile after a keystore save (errors logged). */
function scheduleReconcile() {
  _pending = _pending.then(() => reconcileAll()).catch((err) => {
    emit('WARN', 'KEY_STATUS_TIMELINE_RECONCILE_FAILED', { error: err.message, code: err.code ?? null });
  });
  return _pending;
}

let _hooked = false;
function install() {
  if (_hooked) return;
  _hooked = true;
  _keyStore().onKeysSaved(() => { scheduleReconcile(); });
}

/** @type {any} */ (_col)._afterStart = async () => { install(); await reconcileAll().catch((err) => emit('WARN', 'KEY_STATUS_TIMELINE_RECONCILE_FAILED', { error: err.message })); };

function _reset() { _col._reset(); _pending = Promise.resolve(); }

module.exports = { get, effective, record, reconcileAll, scheduleReconcile, install, _reset };
