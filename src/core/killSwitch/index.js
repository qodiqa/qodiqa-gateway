'use strict';

/**
 * Global kill switch — a signed flag in the control plane that makes the gateway refuse every `/sign` and `/ai/chat`
 * request (BLOCK KILL_SWITCH_ACTIVE) before anything else runs: no provider call, no nonce consumed, no artifact signed.
 *
 * State. One control-plane record (store `kill_switch`, id `global`, migration 096). In production the control plane is
 * PostgreSQL: every replica pulls changes every second and immediately on a signed notification (Redis pub/sub), and
 * REFUSES to answer once its snapshot is older than 5 s (src/core/controlPlane/index.js) — so an activation committed at t
 * is in force on every replica by t + 5 s, or that replica refuses (the gate answers 503 KILL_SWITCH_STATE_UNAVAILABLE).
 * In development/test memory mode the record lives in the process.
 *
 * Integrity. The record carries a MAC (macKeyring purpose KILL_SWITCH, the same keyring that signs control-plane
 * notifications) over its content. A record whose MAC does not verify — someone with database write access changed it —
 * is treated as ACTIVE (fail closed) and escalated: the switch can be raised by tampering, never lowered. A missing record
 * means the switch has never been activated — unless this replica has already seen one: a record that vanishes or whose
 * seq goes backwards after that (tombstone / rollback; migration 097 also refuses both in the database) reads as ACTIVE.
 *
 * Audit. Activation and release write a `KILL_SWITCH` entry to the audit chain (audit schema v8, AUDIT-V8-FREEZE section 3):
 * BLOCK / KILL_SWITCH_ON, ALLOW / KILL_SWITCH_OFF, tenant `*`, executionContext.killSwitch = { operatorId, scope, stateHash }.
 * The switch itself never waits on the audit: an emergency stop must not be blockable by an audit failure or by the v8 flag
 * being off. If the entry cannot be written the change stands and is escalated (CRITICAL KILL_SWITCH_AUDIT_*), and the
 * result says `audit.recorded: false` with the reason.
 */

const crypto = require('crypto');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const macKeyring = require('../security/macKeyring');
const { emit } = require('../../../services/logger');

const RECORD_ID = 'global';
const SCOPE = 'global';
const REASON_MAX = 500;
const MAC_DOMAIN = 'qodiqa-kill-switch-v1';

class KillSwitchError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'KillSwitchError'; this.code = code; this.status = status; }
}

function _metrics() { try { return require('../../observability/metrics'); } catch { return null; } }

// ── record integrity ───────────────────────────────────────────────────────────
function _canonical(r) {
  return JSON.stringify([MAC_DOMAIN, r.active === true, r.eventId, r.operatorId, r.scope, r.reason, r.changedAt, r.seq]);
}
function _stateHash(r) { return crypto.createHash('sha256').update(_canonical(r), 'utf8').digest('hex'); }
function _sign(r) { return macKeyring.sign(macKeyring.PURPOSES.KILL_SWITCH, _canonical(r)); }

let _verifiedCache = { key: null, ok: false, reason: null };
function _verify(r) {
  // keyed by the CONTENT that the MAC covers (not by seq / eventId): a changed field with the old MAC must miss the cache
  const key = `${_canonical(r)}|${r.mac}`;
  if (_verifiedCache.key === key) return _verifiedCache;
  let res;
  try {
    res = typeof r.mac === 'string' && r.mac ? macKeyring.verify(macKeyring.PURPOSES.KILL_SWITCH, _canonical(r), r.mac) : { ok: false, reason: 'NO_MAC' };
  } catch (err) { res = { ok: false, reason: `KEYRING_${err.code || 'ERROR'}` }; }
  _verifiedCache = { key, ok: res.ok === true, reason: res.ok ? null : (res.reason || 'BAD_MAC') };
  return _verifiedCache;
}

// ── state ──────────────────────────────────────────────────────────────────────
let _lastObserved = null;       // 'on' | 'off' | null — transitions are announced once per replica
let _tamperAnnounced = null;
// Highest seq of a record this replica has seen with a valid MAC. A record that later vanishes, or comes back with a lower seq
// (tombstone / rollback of the control-plane row), is a downgrade: treated as ACTIVE and escalated, never as "off".
let _hwm = 0;
let _downgradeAnnounced = null;

function _onChange() {
  // Called by the collection after any change of the snapshot (another replica's write included): keep the gauge true and
  // announce a transition this replica did not cause itself.
  try {
    const s = _readState();
    const now = s.active ? 'on' : 'off';
    if (_lastObserved !== null && _lastObserved !== now) {
      emit('CRITICAL', s.active ? 'KILL_SWITCH_ACTIVE_OBSERVED' : 'KILL_SWITCH_RELEASED_OBSERVED', { seq: s.record ? s.record.seq : null, eventId: s.record ? s.record.eventId : null, tampered: s.tampered });
    }
    _lastObserved = now;
    const m = _metrics();
    if (m && m.killSwitchActive) m.killSwitchActive.set(s.active ? 1 : 0);
  } catch { /* a stale snapshot is reported by the gate itself; observability must not throw from a collection callback */ }
}

const _col = new Collection('kill_switch', { onChange: _onChange });

function _readState() {
  const rec = _col.get(RECORD_ID);
  if (!rec) {
    if (_hwm > 0) return _downgrade('RECORD_MISSING', null);
    return { active: false, record: null, tampered: false };
  }
  const v = _verify(rec);
  if (!v.ok) {
    if (_tamperAnnounced !== rec.mac) {
      _tamperAnnounced = rec.mac;
      emit('CRITICAL', 'KILL_SWITCH_RECORD_TAMPERED', { reason: v.reason, seq: rec.seq ?? null, eventId: rec.eventId ?? null, message: 'The kill-switch record does not carry a valid MAC: treated as ACTIVE.' });
    }
    return { active: true, record: rec, tampered: true };
  }
  if (Number.isSafeInteger(rec.seq) && rec.seq < _hwm) return _downgrade('SEQ_ROLLBACK', rec);
  if (Number.isSafeInteger(rec.seq) && rec.seq > _hwm) _hwm = rec.seq;
  return { active: rec.active === true, record: rec, tampered: false };
}

function _downgrade(reason, rec) {
  const key = `${reason}:${rec ? rec.mac : ''}:${_hwm}`;
  if (_downgradeAnnounced !== key) {
    _downgradeAnnounced = key;
    emit('CRITICAL', 'KILL_SWITCH_RECORD_DOWNGRADED', { reason, seq: rec ? rec.seq ?? null : null, highWaterSeq: _hwm, message: 'The kill-switch record vanished or went back to an older sequence: treated as ACTIVE.' });
  }
  return { active: true, record: rec, tampered: true };
}

/**
 * The current state, synchronously. In PostgreSQL mode this throws a ControlPlaneError (code CONTROL_PLANE_STALE, 503) when
 * the snapshot is older than the 5 s bound — callers must treat that as "cannot be sure" and refuse.
 * @returns {{ active: boolean, record: object|null, tampered: boolean }}
 */
function state() { return _readState(); }

/** The public view of a state (never the MAC). */
function view(s = _readState()) {
  const r = s.record;
  return {
    active: s.active,
    tampered: s.tampered,
    scope: SCOPE,
    seq: r ? r.seq : 0,
    eventId: r ? r.eventId : null,
    operatorId: r ? r.operatorId : null,
    reason: r ? r.reason : null,
    changedAt: r ? r.changedAt : null,
    stateHash: r ? _stateHash(r) : null,
  };
}

// ── audit ──────────────────────────────────────────────────────────────────────
async function _audit(record) {
  const stateHash = _stateHash(record);
  const eb = require('../audit/entryBuilder');
  if (eb.currentSchemaVersion() < 8) {
    emit('CRITICAL', 'KILL_SWITCH_AUDIT_ENTRY_SKIPPED', { eventId: record.eventId, active: record.active, reason: 'AUDIT_SCHEMA_V8_DISABLED', message: 'The kill-switch change is in the control plane and the log; the audit-chain KILL_SWITCH entry needs QODIQA_AUDIT_SCHEMA_V8=true.' });
    return { recorded: false, reason: 'AUDIT_SCHEMA_V8_DISABLED' };
  }
  try {
    const audit = require('../audit/audit-log');
    const entry = await audit.appendMandatory({
      artifactId: `${record.eventId}:kill_switch`,
      entryType: 'KILL_SWITCH',
      decision: record.active ? 'BLOCK' : 'ALLOW',
      reason: record.active ? 'KILL_SWITCH_ON' : 'KILL_SWITCH_OFF',
      tenantId: '*',
      executionContext: { killSwitch: { operatorId: record.operatorId, scope: SCOPE, stateHash } },
    }, { stage: 'KILL_SWITCH', maxRetries: 3, retryDelayMs: 100 });
    return { recorded: true, entryHash: entry ? entry.hash : null, stateHash };
  } catch (err) {
    emit('CRITICAL', 'KILL_SWITCH_AUDIT_FAILED', { eventId: record.eventId, active: record.active, error: err.message, code: err.code ?? null });
    return { recorded: false, reason: 'AUDIT_APPEND_FAILED' };
  }
}

// ── transitions ────────────────────────────────────────────────────────────────
function _validateReason(reason, { required }) {
  if (reason === undefined || reason === null || reason === '') {
    if (required) throw new KillSwitchError('REASON_REQUIRED', 'a reason is required to activate the kill switch');
    return '';
  }
  if (typeof reason !== 'string' || reason.length > REASON_MAX || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw new KillSwitchError('INVALID_REASON', `reason must be a string of at most ${REASON_MAX} characters without control characters`);
  }
  return reason.trim();
}

async function _transition(active, { operatorId, reason }) {
  if (typeof operatorId !== 'string' || !operatorId) throw new KillSwitchError('OPERATOR_REQUIRED', 'an authenticated operator is required', 401);
  const why = _validateReason(reason, { required: active });
  const current = _readState();
  if (current.active === active && !current.tampered) return { changed: false, state: view(current), audit: null };
  const record = {
    active, scope: SCOPE, eventId: crypto.randomUUID(), operatorId, reason: why,
    changedAt: new Date().toISOString(), seq: Math.max(current.record && Number.isSafeInteger(current.record.seq) ? current.record.seq : 0, _hwm) + 1,
  };
  record.mac = _sign(record);
  await _col.put(RECORD_ID, Object.freeze(record), { updatedBy: operatorId });
  _onChange();
  emit('CRITICAL', active ? 'KILL_SWITCH_ACTIVATED' : 'KILL_SWITCH_RELEASED', { eventId: record.eventId, operatorId, scope: SCOPE, seq: record.seq, reason: why, stateHash: _stateHash(record) });
  const m = _metrics();
  if (m && m.killSwitchTransitionsTotal) m.killSwitchTransitionsTotal.inc({ to: active ? 'on' : 'off' });
  const audit = await _audit(record);
  return { changed: true, state: view(_readState()), audit };
}

/** Raise the switch. Idempotent: already active (and intact) → { changed: false }. Needs a reason. */
function activate({ operatorId, reason }) { return _transition(true, { operatorId, reason }); }

/** Lower the switch. Idempotent. A tampered record is replaced by a properly signed one (the release is audited). */
function release({ operatorId, reason }) { return _transition(false, { operatorId, reason }); }

function _resetForTests() { _hwm = 0; _lastObserved = null; _tamperAnnounced = null; _downgradeAnnounced = null; _verifiedCache = { key: null, ok: false, reason: null }; }

module.exports = { _resetForTests, state, view, activate, release, KillSwitchError, RECORD_ID, SCOPE, REASON_MAX, _stateHash, _canonical };
