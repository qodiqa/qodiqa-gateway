'use strict';

/**
 * Audit lifecycle rules for chain walks: schema v7, extended by schema v8
 * (docs/protocol/AUDIT-SCHEMA-V8.md section 4).
 *
 * One tracker per walk. `step(entry)` is called for every hash-verified modern entry, in chain order; it returns null
 * or a failure `{ detail }` (the walk then fails AUDIT_CHAIN_TAMPERED with that detail). `finish()` returns the
 * walk's warnings.
 *
 *   SCHEMA_DOWNGRADE      (failure)  an entry of a lower schemaVersion after an entry of a higher one (v7: a version < 7
 *                                    after the first v7 entry, R-2; v8: a v7 entry after a v8 entry)
 *   MISSING_INTENT        (failure)  a v7+ DECISION whose executingProvider is non-null (the provider was called) with no
 *                                    preceding INTENT for the same requestId — ONLY when the walk is lifecycle-complete,
 *                                    i.e. it starts at GENESIS and can establish the INTENT's absence (C-26)
 *   INTENT_BEFORE_START   (warning)  the same condition in a walk that intentionally starts after GENESIS (a pruned chain
 *                                    from a signed base, checkpoint boot, an incremental progress pointer, any bounded
 *                                    walk): the INTENT may precede the verification boundary; absence is unresolved.
 *                                    Never a failure, never a boot/chain/execution refusal (C-26).
 *   ORPHAN_INTENT         (warning)  an INTENT / STREAM_OPENED with no later DECISION for its requestId in the walk —
 *                                    an incomplete lifecycle (crash, kill, in-flight at the walk's end), not proof of an
 *                                    execution without evidence (R-17)
 *   v8:
 *   COMMIT_WITHOUT_DECISION (failure) a COMMIT whose requestId has no DECISION earlier in the walk — complete walks only
 *   COMMIT_BEFORE_START   (warning)  the same in a bounded walk (the DECISION may precede the boundary)
 *   ORPHAN_DECISION       (warning)  a v8 ALLOW DECISION with an executingProvider, written after the first COMMIT of
 *                                    the chain, with no COMMIT after the commit grace period (default 10 minutes)
 *                                    relative to nowMs (a walk without a clock uses the last entry's timestamp)
 *   ORPHAN_ACTION_INTENT  (warning)  an ACTION_INTENT with no ACTION_COMMIT in the walk
 *   ACTION_ORDER_VIOLATION (failure) an ACTION_INTENT whose actionSeq is not the previous one of its session + 1
 *   APPROVAL_SEQUENCE_VIOLATION (failure) the approval entries of one approvalRef out of order (AUDIT-V8-FREEZE Amendment 2): REQUESTED -> DECIDED(APPROVED) -> [EXPIRED | one
 *                                    ACTION_INTENT carrying the approvalRef] or REQUESTED -> DECIDED(DENIED) or REQUESTED -> EXPIRED, all with the same actionHash; an ACTION_INTENT
 *                                    that names an approvalRef needs the approval to be APPROVED and unspent; in a bounded walk an approval first seen mid-way is accepted
 *                                    (a session first seen mid-walk may start anywhere; from GENESIS it starts at 1)
 *
 * The state is bounded by the open lifecycles of the walk, not by chain length: the decided-requests map is capped
 * (DECIDED_CAP, oldest first); when it overflowed a COMMIT whose DECISION is no longer remembered is a warning, never a
 * failure. Warning lists are capped (counts stay exact).
 */

const { entryTypeOf } = require('./entryBuilder');

const WARNING_SAMPLE_CAP = 100;
const DECIDED_CAP = 200000;
const COMMIT_GRACE_MS = 10 * 60 * 1000;
const WARNING_CODES = ['INTENT_BEFORE_START', 'ORPHAN_INTENT', 'COMMIT_BEFORE_START', 'ORPHAN_DECISION', 'ORPHAN_ACTION_INTENT'];

function createLifecycleTracker({ lifecycleComplete, nowMs, commitGraceMs }) {
  const complete = lifecycleComplete === true;
  const grace = Number.isFinite(commitGraceMs) ? commitGraceMs : COMMIT_GRACE_MS;
  let maxModern = 0;                       // highest schemaVersion >= 7 seen so far
  const open = new Map();                  // requestId → { entryType }
  const decided = new Map();               // requestId → { ts, needsCommit } (v8)
  let evicted = false;
  let firstCommitSeen = false;
  const openActions = new Map();           // `${sessionId}#${actionSeq}` → { sessionId, actionSeq }
  const lastSeq = new Map();               // sessionId → last ACTION_INTENT actionSeq
  const approvals = new Map();             // approvalRef → { hash, state: REQUESTED | APPROVED | DENIED | EXPIRED, spent }
  let approvalsEvicted = false;
  let lastTs = null;
  const counts = Object.fromEntries(WARNING_CODES.map((c) => [c, 0]));
  const samples = Object.fromEntries(WARNING_CODES.map((c) => [c, []]));
  const warn = (code, sample) => {
    counts[code]++;
    if (samples[code].length < WARNING_SAMPLE_CAP) samples[code].push(sample);
  };

  function remember(rid, info) {
    if (decided.size >= DECIDED_CAP) {
      decided.delete(decided.keys().next().value);
      evicted = true;
    }
    decided.set(rid, info);
  }

  // the sequence of one approval (Amendment 2). Unknown references are tolerated in a bounded walk (the earlier entries may precede the boundary).
  function approvalStep(type, entry) {
    const ref = entry.approvalRef; const hash = entry.actionHash;
    const violation = { detail: 'APPROVAL_SEQUENCE_VIOLATION' };
    const known = approvals.get(ref);
    const mayBeUnknown = !complete || approvalsEvicted;
    const remember_ = (st) => { if (approvals.size >= DECIDED_CAP) { approvals.delete(approvals.keys().next().value); approvalsEvicted = true; } approvals.set(ref, st); };
    if (type === 'APPROVAL_REQUESTED') { if (known) return violation; remember_({ hash, state: 'REQUESTED', spent: false }); return null; }
    if (type === 'APPROVAL_DECIDED') {
      const approved = entry.reason === 'APPROVED';
      if (!known) { if (!mayBeUnknown) return violation; remember_({ hash, state: approved ? 'APPROVED' : 'DENIED', spent: false }); return null; }
      if (known.state !== 'REQUESTED' || known.hash !== hash) return violation;
      known.state = approved ? 'APPROVED' : 'DENIED';
      return null;
    }
    if (type === 'APPROVAL_EXPIRED') {
      if (!known) { if (!mayBeUnknown) return violation; remember_({ hash, state: 'EXPIRED', spent: false }); return null; }
      if ((known.state !== 'REQUESTED' && known.state !== 'APPROVED') || known.spent || known.hash !== hash) return violation;
      known.state = 'EXPIRED';
      return null;
    }
    // ACTION_INTENT carrying an approvalRef
    if (!known) { if (!mayBeUnknown) return violation; remember_({ hash, state: 'APPROVED', spent: true }); return null; }
    if (known.state !== 'APPROVED' || known.spent || known.hash !== hash) return violation;
    known.spent = true;
    return null;
  }

  function step(entry) {
    const v = entry.schemaVersion === undefined || entry.schemaVersion === null ? 1 : entry.schemaVersion;
    if (v >= 7) {
      if (v < maxModern) return { detail: 'SCHEMA_DOWNGRADE' };
      maxModern = v;
    } else if (maxModern >= 7) {
      return { detail: 'SCHEMA_DOWNGRADE' };
    }
    if (v < 7) return null;
    if (typeof entry.timestamp === 'string') lastTs = entry.timestamp;

    const type = entryTypeOf(entry);
    const rid = typeof entry.requestId === 'string' && entry.requestId ? entry.requestId : null;
    if (type === 'INTENT' || type === 'STREAM_OPENED') {
      if (rid) open.set(rid, { entryType: type });
      return null;
    }
    if (type === 'COMMIT') {
      const known = rid !== null && decided.get(rid);
      if (known) decided.delete(rid);
      else if (complete && !evicted) return { detail: 'COMMIT_WITHOUT_DECISION' };
      else warn('COMMIT_BEFORE_START', { artifactId: entry.artifactId ?? null, requestId: rid });
      firstCommitSeen = true;
      return null;
    }
    if (type === 'APPROVAL_REQUESTED' || type === 'APPROVAL_DECIDED' || type === 'APPROVAL_EXPIRED' || (type === 'ACTION_INTENT' && entry.approvalRef)) {
      const bad = approvalStep(type, entry);
      if (bad) return bad;
    }
    if (type === 'ACTION_INTENT') {
      const sid = entry.sessionId; const seq = entry.actionSeq;
      if (lastSeq.has(sid)) { if (seq !== lastSeq.get(sid) + 1) return { detail: 'ACTION_ORDER_VIOLATION' }; }
      else if (complete && seq !== 1) return { detail: 'ACTION_ORDER_VIOLATION' };
      lastSeq.set(sid, seq);
      openActions.set(`${sid}#${seq}`, { sessionId: sid, actionSeq: seq });
      return null;
    }
    if (type === 'ACTION_COMMIT') {
      openActions.delete(`${entry.sessionId}#${entry.actionSeq}`);
      return null;
    }
    if (type !== 'DECISION') return null;     // APPROVAL_*, KILL_SWITCH, DLP_TRANSFORM, DELEGATION_*: no lifecycle relation

    // DECISION
    const opened = rid !== null && open.has(rid);
    if (opened) open.delete(rid);
    const executed = entry.executingProvider !== null && entry.executingProvider !== undefined;
    if (v === 8 && rid) {
      remember(rid, { ts: typeof entry.timestamp === 'string' ? Date.parse(entry.timestamp) : NaN, needsCommit: executed && entry.decision === 'ALLOW' && firstCommitSeen });
    }
    if (!executed) return null;                // no provider call
    if (opened) return null;
    if (complete) return { detail: 'MISSING_INTENT' };
    warn('INTENT_BEFORE_START', { artifactId: entry.artifactId ?? null, requestId: rid });
    return null;
  }

  function finish() {
    for (const [requestId, o] of open) warn('ORPHAN_INTENT', { requestId, entryType: o.entryType });
    open.clear();
    for (const [, a] of openActions) warn('ORPHAN_ACTION_INTENT', a);
    openActions.clear();
    approvals.clear();
    const now = Number.isFinite(nowMs) ? nowMs : (lastTs ? Date.parse(lastTs) : NaN);
    if (Number.isFinite(now)) {
      for (const [requestId, d] of decided) {
        if (d.needsCommit && Number.isFinite(d.ts) && now - d.ts > grace) warn('ORPHAN_DECISION', { requestId });
      }
    }
    decided.clear();
    const warnings = [];
    for (const code of WARNING_CODES) {
      if (counts[code] > 0) warnings.push({ code, severity: 'WARNING', count: counts[code], sample: samples[code] });
    }
    return warnings;
  }

  return { step, finish, lifecycleComplete: complete };
}

module.exports = { createLifecycleTracker, WARNING_SAMPLE_CAP, DECIDED_CAP, COMMIT_GRACE_MS };
