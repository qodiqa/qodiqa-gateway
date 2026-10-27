'use strict';

/**
 * Independent verifier — the audit-entry contract (schema v1–v7).
 * No src/ imports: field sets, domain, hashing, entry and chain rules are restated here from
 * the documented contract, so a production change that drifts from the document is caught by
 * the differential tests instead of being silently shared.
 */

const crypto = require('crypto');
const { canonicalize } = require('./canonical');

const AUDIT_DOMAIN = 'QODIQA::AUDIT::V1';
const GENESIS = 'GENESIS';

const V1 = ['artifactId', 'decision', 'inputHash', 'policyHash', 'prevHash', 'requestHash', 'signature', 'timestamp', 'verificationResult'];
const V2 = [...V1, 'publicKeyId', 'schemaVersion'];
const V3 = [...V2, 'consentProvenance', 'policyDecision'];
const V4 = [...V3, 'callerContext'];
const V5 = [...V4, 'provider', 'model'];
const V6 = [...V5, 'stage', 'reason', 'semantic', 'tokenUsage', 'responseId'];
// v7 (SCHEMA-V7-DESIGN.md §2): entryType, outputHash, the three identifiers, the whole executionContext, executingProvider.
const V7 = [...V6, 'entryType', 'outputHash', 'tenantId', 'requestId', 'organizationId', 'executionContext', 'executingProvider'];
// v8 (AUDIT-V8-FREEZE.md section 2): ten more always-present, possibly null fields.
const V8_NEW = ['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'dlp', 'bytesDelivered', 'completionStatus'];
const V8 = [...V7, ...V8_NEW];
const HASHED_FIELDS = Object.freeze({ 1: V1, 2: V2, 3: V3, 4: V4, 5: V5, 6: V6, 7: V7, 8: V8 });
const SUPPORTED_VERSIONS = Object.freeze([1, 2, 3, 4, 5, 6, 7, 8]);

// v7 per-entry shape (SCHEMA-V7-DESIGN.md §3–§5, R-3/R-5/R-8/R-8a): the values are bound by the hash, these are the
// rules the values must satisfy. A DECISION states a 64-hex outputHash; INTENT / STREAM_OPENED have outputHash null
// and the fixed decision/stage pair.
const V7_ENTRY_TYPES = ['DECISION', 'INTENT', 'STREAM_OPENED'];
const V7_LIFECYCLE_FIXED = { INTENT: { decision: 'ALLOW', stage: 'PROVIDER_DISPATCH' }, STREAM_OPENED: { decision: 'ALLOW', stage: 'STREAM_OPENED' } };
function v7Shape(entry) {
  if (entry.schemaVersion !== 7) return null;
  const t = entry.entryType;
  if (!V7_ENTRY_TYPES.includes(t)) return 'INVALID_ENTRY_TYPE';
  if (t === 'DECISION') return (typeof entry.outputHash === 'string' && /^[0-9a-f]{64}$/.test(entry.outputHash)) ? null : 'INVALID_OUTPUT_HASH';
  if (entry.outputHash !== null && entry.outputHash !== undefined) return 'INVALID_ENTRY_SHAPE';
  const fx = V7_LIFECYCLE_FIXED[t];
  return (entry.decision === fx.decision && entry.stage === fx.stage) ? null : 'INVALID_ENTRY_SHAPE';
}

// ── v8 entry shape (AUDIT-V8-FREEZE.md section 3), restated independently of src/ ──────────────────────────────────────
// Per NEW type: [decision → allowed reasons], stage, artifactId suffix, whether it carries an outputHash, whether it is a
// system entry (signature SYSTEM, verificationResult false), the v8 fields it may carry / must carry, and the frozen
// executionContext key. The three v7 types keep their v7 rules and may carry only the listed v8 fields.
const V8_NEW_TYPES = {
  COMMIT: { st: 'COMMIT', rs: { ALLOW: ['RESPONSE_DELIVERED', 'RESPONSE_FAILED'] }, sfx: ':commit', out: true, sys: false, may: ['issuedAt', 'protocolVersion', 'bytesDelivered', 'completionStatus'], must: ['bytesDelivered', 'completionStatus'], ctx: null },
  ACTION_INTENT: { st: 'ACTION_DISPATCH', rs: { ALLOW: ['ACTION_AUTHORIZED'] }, sfx: ':action_intent', out: false, sys: false, may: ['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef'], must: ['agentId', 'sessionId', 'actionSeq', 'actionHash'], ctx: 'action' },
  ACTION_COMMIT: { st: 'ACTION_COMMIT', rs: { ALLOW: ['ACTION_COMPLETED', 'ACTION_FAILED'] }, sfx: ':action_commit', out: true, sys: false, may: ['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'completionStatus'], must: ['agentId', 'sessionId', 'actionSeq', 'actionHash', 'completionStatus'], ctx: 'action' },
  APPROVAL_REQUESTED: { st: 'APPROVAL', rs: { BLOCK: ['APPROVAL_REQUIRED'] }, sfx: ':approval_requested', out: false, sys: true, may: ['approvalRef', 'actionHash'], must: ['approvalRef', 'actionHash'], ctx: 'approval' },
  APPROVAL_DECIDED: { st: 'APPROVAL', rs: { ALLOW: ['APPROVED'], BLOCK: ['DENIED'] }, sfx: ':approval_decided', out: false, sys: true, may: ['approvalRef', 'actionHash'], must: ['approvalRef', 'actionHash'], ctx: 'approval' },
  APPROVAL_EXPIRED: { st: 'APPROVAL', rs: { BLOCK: ['APPROVAL_EXPIRED'] }, sfx: ':approval_expired', out: false, sys: true, may: ['approvalRef', 'actionHash'], must: ['approvalRef', 'actionHash'], ctx: 'approval' },
  KILL_SWITCH: { st: 'KILL_SWITCH', rs: { BLOCK: ['KILL_SWITCH_ON'], ALLOW: ['KILL_SWITCH_OFF'] }, sfx: ':kill_switch', out: false, sys: true, may: [], must: [], ctx: 'killSwitch' },
  DLP_TRANSFORM: { st: 'DLP', rs: { ALLOW: ['DLP_DETECT', 'DLP_REDACT', 'DLP_MASK'], BLOCK: ['DLP_BLOCK'] }, re: /:dlp_(in|out)_[0-9]+$/, out: false, sys: true, may: ['dlp'], must: ['dlp'], ctx: null },
  DELEGATION_ISSUED: { st: 'DELEGATION', rs: { ALLOW: ['DELEGATION_ISSUED'] }, sfx: ':delegation_issued', out: false, sys: true, may: [], must: [], ctx: 'delegation' },
  DELEGATION_REVOKED: { st: 'DELEGATION', rs: { ALLOW: ['DELEGATION_REVOKED'] }, sfx: ':delegation_revoked', out: false, sys: true, may: [], must: [], ctx: 'delegation' },
};
const V8_OLD_TYPES_MAY = { DECISION: ['issuedAt', 'protocolVersion', 'completionStatus'], INTENT: ['issuedAt', 'protocolVersion'], STREAM_OPENED: ['issuedAt', 'protocolVersion'] };
const COMPLETION = ['COMPLETE', 'CANCELLED', 'ERROR', 'TIMEOUT', 'CLIENT_DISCONNECTED', 'OUTCOME_UNKNOWN'];
const isInt = (v, min) => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
const nonEmpty = (v) => typeof v === 'string' && v.length > 0;
const hex64 = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const V8_VALID = {
  issuedAt: (v) => isInt(v, 0), protocolVersion: (v) => isInt(v, 1), agentId: nonEmpty, sessionId: nonEmpty, approvalRef: nonEmpty,
  actionSeq: (v) => isInt(v, 1), actionHash: hex64, bytesDelivered: (v) => isInt(v, 0), completionStatus: (v) => COMPLETION.includes(v),
  dlp: (v) => isObjectLike(v) && Array.isArray(v.rules) && v.rules.every(nonEmpty) && ['DETECT', 'REDACT', 'BLOCK', 'MASK'].includes(v.action) && hex64(v.inputHashBefore) && hex64(v.inputHashAfter),
};
function isObjectLike(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
const none = (v) => v === null || v === undefined;
function v8Shape(entry) {
  if (entry.schemaVersion !== 8) return null;
  const t = entry.entryType;
  const old = V8_OLD_TYPES_MAY[t]; const nu = V8_NEW_TYPES[t];
  if (!old && !nu) return 'INVALID_ENTRY_TYPE';
  const may = old || nu.may;
  for (const f of V8_NEW) {
    if (none(entry[f])) continue;
    if (!may.includes(f)) return 'INVALID_ENTRY_SHAPE';
    if (!V8_VALID[f](entry[f])) return 'INVALID_V8_FIELD';
  }
  if (old) {
    if (t === 'DECISION') return hex64(entry.outputHash) ? null : 'INVALID_OUTPUT_HASH';
    if (!none(entry.outputHash)) return 'INVALID_ENTRY_SHAPE';
    const fx = V7_LIFECYCLE_FIXED[t];
    return (entry.decision === fx.decision && entry.stage === fx.stage) ? null : 'INVALID_ENTRY_SHAPE';
  }
  if (nu.must.some((f) => none(entry[f]))) return 'INVALID_V8_FIELD';
  const reasons = nu.rs[entry.decision];
  if (!reasons || !reasons.includes(entry.reason) || entry.stage !== nu.st) return 'INVALID_ENTRY_SHAPE';
  if (t === 'DLP_TRANSFORM' && entry.reason !== 'DLP_' + entry.dlp.action) return 'INVALID_ENTRY_SHAPE';
  const id = entry.artifactId;
  const idOk = typeof id === 'string' && (nu.re ? nu.re.test(id) : (id.endsWith(nu.sfx) && id.length > nu.sfx.length));
  if (!idOk) return 'INVALID_ENTRY_SHAPE';
  if (nu.out ? !hex64(entry.outputHash) : !none(entry.outputHash)) return 'INVALID_OUTPUT_HASH';
  if (entry.verificationResult !== !nu.sys) return 'INVALID_ENTRY_SHAPE';
  if (nu.sys && entry.signature !== 'SYSTEM') return 'INVALID_ENTRY_SHAPE';
  if (entry.inputHash !== 'UNAVAILABLE' || entry.requestHash !== 'UNAVAILABLE' || entry.policyHash !== 'UNAVAILABLE') return 'INVALID_ENTRY_SHAPE';
  for (const f of ['publicKeyId', 'provider', 'model', 'executingProvider', 'semantic', 'tokenUsage', 'responseId', 'consentProvenance', 'policyDecision', 'callerContext']) {
    if (!none(entry[f])) return 'INVALID_ENTRY_SHAPE';
  }
  const ctx = entry.executionContext;
  if (nu.ctx === null) return none(ctx) ? null : 'INVALID_ENTRY_SHAPE';
  return (isObjectLike(ctx) && isObjectLike(ctx[nu.ctx])) ? null : 'INVALID_ENTRY_SHAPE';
}

function auditHash(canonical) {
  return crypto.createHash('sha256').update(AUDIT_DOMAIN, 'utf8').update(canonical, 'utf8').digest('hex');
}

/** The schema version an entry declares: absent/null → 1; 1..6 → itself; anything else → null (unsupported). */
function declaredVersion(entry) {
  const v = entry.schemaVersion;
  if (v === undefined || v === null) return 1;
  return SUPPORTED_VERSIONS.includes(v) ? v : null;
}

/** The canonical string an entry's own field values produce under its declared version. */
function expectedCanonical(entry) {
  const v = declaredVersion(entry);
  if (v === null) return null;
  const core = {};
  for (const f of HASHED_FIELDS[v]) core[f] = entry[f];
  return canonicalize(core);
}

/** Per-entry integrity: canonical string == canonical(fields), hash == H(domain ‖ canonical). */
function checkEntryHash(entry) {
  const version = declaredVersion(entry);
  if (version === null) return { ok: false, code: 'UNSUPPORTED_SCHEMA_VERSION', version: entry.schemaVersion };
  if (typeof entry.canonical !== 'string') return { ok: false, code: 'CANONICAL_MISSING', version };
  const recomputedHash = auditHash(entry.canonical);
  if (recomputedHash !== entry.hash) return { ok: false, code: 'HASH_MISMATCH', version, expectedHash: recomputedHash };
  let canonical;
  try { canonical = expectedCanonical(entry); } catch (e) { return { ok: false, code: 'CANONICALIZATION_ERROR:' + e.code, version }; }
  if (canonical !== entry.canonical) return { ok: false, code: 'CANONICAL_FIELD_MISMATCH', version };
  const shape = v7Shape(entry) || v8Shape(entry);
  if (shape) return { ok: false, code: shape, version };
  return { ok: true, code: null, version };
}

const isObj = (e) => !!e && typeof e === 'object' && !Array.isArray(e);

// ── mirror projection, restated independently ──
// A PostgreSQL row with mirror_encoding = 1 holds P(value) in every per-field column (TEXT, and every string value and
// object key inside JSONB). P⁻¹: `\\` → `\`, `\"` → `"`, `\u` + 4 lowercase hex → that UTF-16 code unit, any other
// printable-ASCII character → itself; anything else is a decode error (the row is reported, never guessed).
// mirror_encoding 0 / absent = native values, used as stored. canonical / hash / prev_hash are never projected.
const MIRROR_DECODE_ERROR = Symbol('mirrorDecodeError');
function mirrorDecodeString(t) {
  if (typeof t !== 'string') throw new Error('not a string');
  let out = '';
  for (let i = 0; i < t.length; i++) {
    const ch = t[i]; const c = t.charCodeAt(i);
    if (ch === '\\') {
      const n = t[i + 1];
      if (n === '\\' || n === '"') { out += n; i += 1; continue; }
      if (n === 'u' && /^[0-9a-f]{4}$/.test(t.slice(i + 2, i + 6))) { out += String.fromCharCode(parseInt(t.slice(i + 2, i + 6), 16)); i += 5; continue; }
      throw new Error(`bad escape at ${i}`);
    }
    if (c < 0x20 || c > 0x7e || ch === '"') throw new Error(`code unit U+${c.toString(16)} at ${i} is not a projected character`);
    out += ch;
  }
  return out;
}
function mirrorDecodeJson(v) {
  if (typeof v === 'string') return mirrorDecodeString(v);
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(mirrorDecodeJson);
  const o = {};
  for (const k of Object.keys(v)) {
    const dk = mirrorDecodeString(k);
    if (Object.prototype.hasOwnProperty.call(o, dk)) throw new Error('duplicate key after decoding');
    Object.defineProperty(o, dk, { value: mirrorDecodeJson(v[k]), enumerable: true, configurable: true, writable: true });
  }
  return o;
}
const hasStoredLegacyKey = (e) => Object.prototype.propertyIsEnumerable.call(e, 'legacy');
const isLegacyShaped = (e) => !('inputHash' in e) || e.inputHash === null || e.inputHash === undefined;

/**
 * Walk an ordered chain, mirroring the production full-chain verdict (SCHEMA-V6 §5): the
 * FIRST failure decides the chain verdict and its reason code; every entry still gets its own
 * per-entry hash result so a report shows exactly which lines are intact.
 *
 * opts.startPrevHash       — expected prevHash of the first chained entry (default GENESIS)
 * opts.tolerateLegacyPrefix — report pre-hash lines in the GENESIS prefix as UNVERIFIED_LEGACY
 *                             instead of failing (the boot loader's tolerance; the full-disk
 *                             verifier's verdict is AUDIT_ENTRY_MISSING)
 *
 * v7 lifecycle rules (SCHEMA-V7-DESIGN.md §8 R-2/R-17, amended by C-26 §13), applied to every verified entry in order:
 *   SCHEMA_DOWNGRADE     failure  an entry with schemaVersion < 7 after the walk's first v7 entry
 *   MISSING_INTENT       failure  a v7 DECISION with non-null executingProvider and no earlier INTENT/STREAM_OPENED
 *                                 for its requestId — ONLY when the walk starts at GENESIS (lifecycleComplete)
 *   INTENT_BEFORE_START  warning  the same condition in a walk that starts after GENESIS (the INTENT may precede the
 *                                 verification boundary; absence cannot be established)
 *   ORPHAN_INTENT        warning  an INTENT/STREAM_OPENED with no later DECISION for its requestId in the walk
 */
// the walk is incremental (createChainWalker: push one entry at a time, result() at the end) so the
// CLI can verify a log of any size without holding it; walkChain() is the same walker over an array, so both give
// identical verdicts by construction. `perEntryLimit` (streaming only): once more rows than that were walked, VERIFIED /
// AFTER_FAILURE rows are no longer kept (counted instead) and the result says perEntryTruncated.
function createChainWalker({ startPrevHash = GENESIS, tolerateLegacyPrefix = false, perEntryLimit = Infinity, nowMs, commitGraceMs = 10 * 60 * 1000 } = {}) {
  let last = startPrevHash;
  let head = null; let tail = null; let verified = 0; let legacyUnverified = 0;
  let failure = null;
  const seen = new Set();
  let perEntry = [];
  let truncated = false; let total = 0;
  const statusCounts = {}; const versionCounts = {};
  const lifecycleComplete = startPrevHash === GENESIS;
  let maxModern = 0;                          // highest schemaVersion >= 7 seen
  const openLifecycle = new Map();
  const warningCounts = { INTENT_BEFORE_START: 0, ORPHAN_INTENT: 0, COMMIT_BEFORE_START: 0, ORPHAN_DECISION: 0, ORPHAN_ACTION_INTENT: 0 };
  // v8 (AUDIT-V8-FREEZE section 4): decided requests awaiting their COMMIT (capped; an overflow turns an unknown COMMIT into a warning),
  // open action intents, last action sequence per session.
  const DECIDED_CAP = 200000;
  const decided = new Map(); let decidedEvicted = false; let firstCommit = false;
  const openActions = new Set(); const lastSeq = new Map(); let lastTs = null;
  const approvals = new Map(); let approvalsEvicted = false;          // approvalRef -> { hash, state, spent } (AUDIT-V8-FREEZE Amendment 2)
  const fail = (i, reason, detail, extra = {}) => {
    if (!failure) failure = { index: i, reason, detail, ...extra };
  };
  const keep = (row) => !truncated || (row.status !== 'VERIFIED' && row.status !== 'AFTER_FAILURE');

  function step(entry, i, row) {
    if (!isObj(entry)) { row.status = 'NOT_AN_OBJECT'; fail(i, 'AUDIT_ENTRY_MISSING', 'NOT_AN_OBJECT'); return; }
    if (entry[MIRROR_DECODE_ERROR]) { row.status = failure ? 'AFTER_FAILURE' : 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'MIRROR_DECODE_ERROR', { mirrorDecodeError: entry[MIRROR_DECODE_ERROR] }); return; }
    row.schemaVersion = entry.schemaVersion ?? null;
    const h = isLegacyShaped(entry) ? null : checkEntryHash(entry);
    row.hash = h ? (h.ok ? 'OK' : h.code) : 'N/A';
    if (failure) { row.status = 'AFTER_FAILURE'; return; }

    if (typeof entry.timestamp !== 'string') { row.status = 'FAIL'; fail(i, 'AUDIT_ENTRY_MISSING', 'timestamp'); return; }
    if (typeof entry.artifactId !== 'string') { row.status = 'FAIL'; fail(i, 'AUDIT_ENTRY_MISSING', 'artifactId'); return; }
    if (hasStoredLegacyKey(entry)) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'STORED_LEGACY_FLAG'); return; }
    // A pre-hash (legacy-shaped) line has nothing to verify. The full-chain verdict refuses it
    // through the ordinary checks below (AUDIT_ENTRY_MISSING at inputHash, or a duplicate id);
    // only the boot loader's tolerance — opt-in here — accepts it, and only in the GENESIS prefix.
    if (isLegacyShaped(entry) && tolerateLegacyPrefix && last === GENESIS && startPrevHash === GENESIS) {
      row.status = 'UNVERIFIED_LEGACY'; legacyUnverified++; return;
    }
    if (seen.has(entry.artifactId)) { row.status = 'FAIL'; fail(i, 'AUDIT_DUPLICATE_ENTRY', 'artifactId'); return; }
    seen.add(entry.artifactId);
    for (const f of ['prevHash', 'hash', 'inputHash', 'decision']) {
      if (typeof entry[f] !== 'string') { row.status = 'FAIL'; fail(i, 'AUDIT_ENTRY_MISSING', f); return; }
    }
    if (typeof entry.signature !== 'string' || !entry.signature) { row.status = 'FAIL'; fail(i, 'AUDIT_ENTRY_MISSING', 'signature'); return; }
    if (entry.prevHash !== last) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_BROKEN', 'prevHash', { expectedPrevHash: last, actualPrevHash: entry.prevHash }); return; }
    if (typeof entry.canonical !== 'string') { row.status = 'FAIL'; fail(i, 'AUDIT_ENTRY_MISSING', 'canonical'); return; }
    if (!h.ok) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', h.code); return; }
    const v = h.version;
    if (v >= 7) {
      if (v < maxModern) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'SCHEMA_DOWNGRADE'); return; }
      maxModern = v;
    } else if (maxModern >= 7) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'SCHEMA_DOWNGRADE'); return; }
    if (v >= 7) {
      if (typeof entry.timestamp === 'string') lastTs = entry.timestamp;
      const rid = typeof entry.requestId === 'string' && entry.requestId ? entry.requestId : null;
      const t = entry.entryType;
      const executed = entry.executingProvider !== null && entry.executingProvider !== undefined;
      if (t === 'INTENT' || t === 'STREAM_OPENED') {
        if (rid) openLifecycle.set(rid, t);
      } else if (t === 'COMMIT') {
        if (rid !== null && decided.has(rid)) decided.delete(rid);
        else if (lifecycleComplete && !decidedEvicted) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'COMMIT_WITHOUT_DECISION'); return; }
        else warningCounts.COMMIT_BEFORE_START++;
        firstCommit = true;
      } else if (t === 'APPROVAL_REQUESTED' || t === 'APPROVAL_DECIDED' || t === 'APPROVAL_EXPIRED') {
        const ref = entry.approvalRef; const hash = entry.actionHash; const known = approvals.get(ref);
        const unknownOk = !lifecycleComplete || approvalsEvicted;
        const put = (st) => { if (approvals.size >= DECIDED_CAP) { approvals.delete(approvals.keys().next().value); approvalsEvicted = true; } approvals.set(ref, st); };
        let bad = false;
        if (t === 'APPROVAL_REQUESTED') { if (known) bad = true; else put({ hash, state: 'REQUESTED', spent: false }); }
        else if (t === 'APPROVAL_DECIDED') {
          const approved = entry.reason === 'APPROVED';
          if (!known) { if (unknownOk) put({ hash, state: approved ? 'APPROVED' : 'DENIED', spent: false }); else bad = true; }
          else if (known.state !== 'REQUESTED' || known.hash !== hash) bad = true; else known.state = approved ? 'APPROVED' : 'DENIED';
        } else if (!known) { if (unknownOk) put({ hash, state: 'EXPIRED', spent: false }); else bad = true; }
        else if ((known.state !== 'REQUESTED' && known.state !== 'APPROVED') || known.spent || known.hash !== hash) bad = true; else known.state = 'EXPIRED';
        if (bad) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'APPROVAL_SEQUENCE_VIOLATION'); return; }
      } else if (t === 'ACTION_INTENT') {
        if (entry.approvalRef) {
          const ref = entry.approvalRef; const known = approvals.get(ref);
          if (!known) {
            if (!lifecycleComplete || approvalsEvicted) { if (approvals.size >= DECIDED_CAP) { approvals.delete(approvals.keys().next().value); approvalsEvicted = true; } approvals.set(ref, { hash: entry.actionHash, state: 'APPROVED', spent: true }); }
            else { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'APPROVAL_SEQUENCE_VIOLATION'); return; }
          } else if (known.state !== 'APPROVED' || known.spent || known.hash !== entry.actionHash) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'APPROVAL_SEQUENCE_VIOLATION'); return; }
          else known.spent = true;
        }
        const sid = entry.sessionId; const seq = entry.actionSeq;
        const bad = lastSeq.has(sid) ? seq !== lastSeq.get(sid) + 1 : (lifecycleComplete && seq !== 1);
        if (bad) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'ACTION_ORDER_VIOLATION'); return; }
        lastSeq.set(sid, seq); openActions.add(sid + '#' + seq);
      } else if (t === 'ACTION_COMMIT') {
        openActions.delete(entry.sessionId + '#' + entry.actionSeq);
      } else if (t === 'DECISION' || t === undefined) {
        const opened = rid !== null && openLifecycle.has(rid);
        if (opened) openLifecycle.delete(rid);
        if (v === 8 && rid) {
          if (decided.size >= DECIDED_CAP) { decided.delete(decided.keys().next().value); decidedEvicted = true; }
          decided.set(rid, { ts: typeof entry.timestamp === 'string' ? Date.parse(entry.timestamp) : NaN, needs: executed && entry.decision === 'ALLOW' && firstCommit });
        }
        if (executed && !opened) {
          if (lifecycleComplete) { row.status = 'FAIL'; fail(i, 'AUDIT_CHAIN_TAMPERED', 'MISSING_INTENT'); return; }
          warningCounts.INTENT_BEFORE_START++;
        }
      }
    }
    row.status = 'VERIFIED';
    if (head === null) head = entry.hash;
    tail = entry.hash; last = entry.hash; verified++;
  }

  return {
    push(entry) {
      const i = total++;
      const row = { index: i, artifactId: isObj(entry) ? entry.artifactId ?? null : null, status: null };
      step(entry, i, row);
      statusCounts[row.status] = (statusCounts[row.status] || 0) + 1;
      const vk = row.schemaVersion ?? 'none'; versionCounts[vk] = (versionCounts[vk] || 0) + 1;
      if (keep(row)) perEntry.push(row);
      if (!truncated && perEntry.length > perEntryLimit) { truncated = true; perEntry = perEntry.filter(keep); }
    },
    result() {
      warningCounts.ORPHAN_INTENT = failure ? 0 : openLifecycle.size;
      warningCounts.ORPHAN_ACTION_INTENT = failure ? 0 : openActions.size;
      if (!failure) {
        const now = Number.isFinite(nowMs) ? nowMs : (lastTs ? Date.parse(lastTs) : NaN);
        let n = 0;
        if (Number.isFinite(now)) for (const d of decided.values()) if (d.needs && Number.isFinite(d.ts) && now - d.ts > commitGraceMs) n++;
        warningCounts.ORPHAN_DECISION = n;
      }
      const warnings = failure ? [] : Object.entries(warningCounts).filter(([, n]) => n > 0).map(([code, count]) => ({ code, severity: 'WARNING', count }));
      return {
        valid: !failure, reason: failure ? failure.reason : null, failure,
        entriesVerified: verified, legacyUnverified, head, tail, total, perEntry,
        lifecycleComplete, warnings,
        ...(truncated ? { perEntryTruncated: true, statusCounts: { ...statusCounts }, schemaVersionCounts: { ...versionCounts } } : {}),
      };
    },
  };
}

function walkChain(entries, opts = {}) {
  const w = createChainWalker(opts);
  for (const e of entries) w.push(e);
  return w.result();
}

/**
 * Parse an NDJSON audit log exactly as the production reader does: split on "\n", trim each
 * line, skip empty lines, JSON.parse each; a line that does not parse is a hard failure.
 */
function parseNdjson(text) {
  const entries = []; const lineByteLengths = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    let v;
    try { v = JSON.parse(line); } catch { return { ok: false, error: 'MALFORMED_JSON', line: i + 1, entries }; }
    entries.push(v);
    lineByteLengths.push(Buffer.byteLength(lines[i], 'utf8') + 1);
  }
  return { ok: true, entries, lineByteLengths };
}

/**
 * A PostgreSQL audit_chain row (snake_case, as `SELECT *` / the forensic dumps) → the entry
 * shape the production loader builds (SCHEMA-V6 §6.3): `timestamp` comes from the stored
 * canonical, v3–v6 hashed columns default to null, tenantId/nonce/executionContext stay unset
 * when null.
 */
function entryFromPgRow(r0) {
  // decode a projected row (mirror_encoding 1) at the row → entry boundary; a corrupt value or an unknown marker
  // yields an entry carrying MIRROR_DECODE_ERROR, which walkChain() fails explicitly at its position.
  let r = r0;
  const enc = r0.mirror_encoding === undefined || r0.mirror_encoding === null ? 0 : Number(r0.mirror_encoding);
  let decodeError = null;
  if (enc === 1) {
    try {
      r = { ...r0 };
      for (const c of MIRROR_TEXT_COLUMNS) if (r[c] !== null && r[c] !== undefined) r[c] = mirrorDecodeString(r[c]);
      for (const c of MIRROR_JSON_COLUMNS) if (r[c] !== null && r[c] !== undefined) r[c] = mirrorDecodeJson(r[c]);
    } catch (e) { decodeError = e.message; r = r0; }
  } else if (enc !== 0) {
    decodeError = `unknown mirror_encoding ${JSON.stringify(r0.mirror_encoding)}`;
  }
  let timestamp = null;
  try { timestamp = JSON.parse(r.canonical).timestamp ?? null; } catch { /* left null → verdict flags it */ }
  const e = {
    hash: r.hash, prevHash: r.prev_hash, canonical: r.canonical, artifactId: r.artifact_id, decision: r.decision,
    highResTime: r.high_res_time, inputHash: r.input_hash, signature: r.signature, requestHash: r.request_hash,
    policyHash: r.policy_hash, verificationResult: r.verification_result, publicKeyId: r.public_key_id ?? null,
    schemaVersion: r.schema_version === undefined || r.schema_version === null ? null : Number(r.schema_version),
    consentProvenance: r.consent_provenance ?? null, policyDecision: r.policy_decision ?? null,
    callerContext: r.caller_context ?? null, provider: r.provider ?? null, model: r.model ?? null,
    stage: r.stage ?? null, reason: r.reason ?? null, semantic: r.semantic ?? null,
    tokenUsage: r.token_usage ?? null, responseId: r.response_id ?? null, timestamp,
    // v7 columns (migration 075); null for schema_version < 7
    entryType: r.entry_type ?? null, outputHash: r.output_hash ?? null, requestId: r.request_id ?? null,
    organizationId: r.organization_id ?? null, executingProvider: r.executing_provider ?? null,
  };
  if (e.schemaVersion === 8) {
    // v8 columns (migration 083); BIGINT columns arrive as strings from pg
    const num = (x) => (x === undefined || x === null ? null : Number(x));
    Object.assign(e, {
      issuedAt: num(r.issued_at), protocolVersion: num(r.protocol_version), agentId: r.agent_id ?? null, sessionId: r.session_id ?? null,
      actionSeq: num(r.action_seq), actionHash: r.action_hash ?? null, approvalRef: r.approval_ref ?? null, dlp: r.dlp ?? null,
      bytesDelivered: num(r.bytes_delivered), completionStatus: r.completion_status ?? null,
    });
  }
  if (r.tenant_id != null) e.tenantId = r.tenant_id;
  if (r.nonce != null) e.nonce = r.nonce;
  if (r.execution_context != null) e.executionContext = r.execution_context;
  if (decodeError) Object.defineProperty(e, MIRROR_DECODE_ERROR, { value: decodeError, enumerable: false });
  return e;
}
const MIRROR_TEXT_COLUMNS = ['artifact_id', 'decision', 'high_res_time', 'input_hash', 'signature', 'request_hash', 'policy_hash', 'nonce', 'tenant_id',
  'public_key_id', 'provider', 'model', 'stage', 'reason', 'response_id', 'entry_type', 'output_hash', 'request_id', 'organization_id', 'executing_provider',
  'agent_id', 'session_id', 'action_hash', 'approval_ref', 'completion_status'];
const MIRROR_JSON_COLUMNS = ['execution_context', 'consent_provenance', 'policy_decision', 'caller_context', 'semantic', 'token_usage', 'dlp'];

/**
 * Order PG rows by hash link (the production loader's order; seq may be inverted on
 * earlier single-node mirrors). Returns { ordered, anomalies }: a fork (two rows claiming the
 * same prevHash), an orphan (unreachable row), two GENESIS rows, or a cycle leaves rows out of
 * `ordered` and is reported; seq duplicates/gaps/inversions are reported alongside.
 */
function orderPgRows(rows, { start = GENESIS } = {}) {
  // M3: after a retention prune the rows start at the signed base record's headHash (`start`), not GENESIS.
  const anomalies = [];
  const byPrev = new Map();
  for (const r of rows) {
    if (byPrev.has(r.prev_hash)) anomalies.push({ type: 'FORK', prevHash: r.prev_hash, seqs: [String(byPrev.get(r.prev_hash).seq), String(r.seq)] });
    else byPrev.set(r.prev_hash, r);
  }
  const genesis = rows.filter((r) => r.prev_hash === start);
  const label = start === GENESIS ? 'GENESIS' : 'START';
  if (rows.length > 0 && genesis.length !== 1) anomalies.push({ type: genesis.length ? `MULTIPLE_${label}` : `NO_${label}`, count: genesis.length });
  const ordered = []; const used = new Set();
  let cur = byPrev.get(start);
  while (cur && !used.has(cur)) { ordered.push(cur); used.add(cur); cur = byPrev.get(cur.hash); }
  const orphans = rows.filter((r) => !used.has(r));
  if (orphans.length) anomalies.push({ type: 'UNREACHABLE_ROWS', seqs: orphans.map((r) => String(r.seq)) });
  const seqs = rows.map((r) => Number(r.seq));
  const dup = seqs.filter((s, i) => seqs.indexOf(s) !== i);
  if (dup.length) anomalies.push({ type: 'DUPLICATE_SEQ', seqs: [...new Set(dup)] });
  let inversions = 0;
  for (let i = 1; i < ordered.length; i++) if (Number(ordered[i].seq) < Number(ordered[i - 1].seq)) inversions++;
  if (inversions) anomalies.push({ type: 'SEQ_INVERSION', count: inversions, severity: 'WARN' });
  const sorted = [...new Set(seqs)].sort((a, b) => a - b);
  let gaps = 0;
  for (let i = 1; i < sorted.length; i++) if (sorted[i] !== sorted[i - 1] + 1) gaps++;
  if (gaps) anomalies.push({ type: 'SEQ_GAP', count: gaps, severity: 'WARN' });
  return { ordered, anomalies };
}

/**
 * The checksum anchor {count, tailHash, v2?} against the log it claims to describe (SCHEMA-V6 §7).
 * The anchor is UNSIGNED (A3-07): it detects truncation/rollback by a party that did not also
 * rewrite it, nothing more.
 */
function checkAnchor(anchor, entries, lineByteLengths, offset = 0) {
  const c = createAnchorChecker(anchor, offset);
  for (let i = 0; i < entries.length; i++) c.push(entries[i], lineByteLengths[i] ?? 0);
  return c.result();
}

// checkAnchor() one entry at a time (the same checks on the same quantities: the entry count, the entry at the
// anchor's position, the byte length and modern count of the anchored prefix, the prefix's first modern hash).
function createAnchorChecker(anchor, offset = 0) {
  if (!anchor || !Number.isInteger(anchor.count) || anchor.count < 0) return { push() {}, result: () => ({ ok: false, problems: ['ANCHOR_MALFORMED'] }) };
  if (anchor.count < offset) return { push() {}, result: () => ({ ok: false, problems: ['ANCHOR_BELOW_BASE'] }) };
  const n = anchor.count - offset;
  let count = 0; let atN1; let bytes = 0; let modernCount = 0; let firstModern;
  return {
    push(entry, lineBytes) {
      const idx = count++;
      if (idx < n) {
        bytes += lineBytes;
        if (isObj(entry) && !isLegacyShaped(entry)) { modernCount++; if (firstModern === undefined) firstModern = entry; }
      }
      if (idx === n - 1) atN1 = entry;
    },
    result() {
      // M3: after a retention prune the log holds entries offset+1..N while the anchor's counts stay LIFETIME
      // (count, v2.totalCount, v2.modernCount); v2.byteLength describes the file as it is; v2.headHash is the lifetime
      // first entry, which lives in the archive — not checkable from the suffix (reported as such).
      const problems = [];
      const truncated = count < n;
      if (truncated) problems.push('LOG_SHORTER_THAN_ANCHOR');
      else if (n > 0 && anchor.tailHash) {
        const at = atN1;
        if (at && !isLegacyShaped(at) && at.hash !== anchor.tailHash) problems.push('TAIL_HASH_MISMATCH');
      }
      if (anchor.v2 && truncated) {
        // the prefix the v2 block describes is not all present — its content checks cannot be evaluated
        if (Number.isInteger(anchor.v2.totalCount) && anchor.v2.totalCount !== anchor.count) problems.push('V2_TOTAL_COUNT_DISAGREES');
      } else if (anchor.v2) {
        const v2 = anchor.v2;
        if (Number.isInteger(v2.totalCount) && v2.totalCount !== anchor.count) problems.push('V2_TOTAL_COUNT_DISAGREES');
        if (Number.isInteger(v2.byteLength)) {
          if (count >= n && bytes !== v2.byteLength) problems.push('V2_BYTE_LENGTH_DISAGREES');
        }
        if (Number.isInteger(v2.modernCount) && v2.modernCount !== modernCount + offset) problems.push('V2_MODERN_COUNT_DISAGREES');
        if (v2.headHash !== undefined && offset === 0 && (firstModern?.hash ?? null) !== v2.headHash) problems.push('V2_HEAD_HASH_DISAGREES');
      }
      return { ok: problems.length === 0, problems, ...(offset > 0 ? { headHashCheckedAgainstArchive: false } : {}) };
    },
  };
}

// parseNdjson() over a FILE without reading it into one string: the same splitting on newline (a UTF-8 byte 0x0A
// is never part of a multi-byte sequence, so splitting bytes = splitting the decoded text), trim, skip empty lines,
// JSON.parse; visit(entry, lineByteLength) per entry (return false to stop early). Returns { ok: true, entries: n } or { ok: false, error:
// 'MALFORMED_JSON', line } (1-based physical line, as parseNdjson reports it).
function forEachNdjsonEntry(file, visit, { chunkBytes = 1 << 20 } = {}) {
  const fs = require('fs');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(chunkBytes);
    let carry = null; let lineNo = 0; let n = 0; let pos = 0;
    const handle = (lineBuf) => {
      lineNo++;
      const raw = lineBuf.toString('utf8');
      const line = raw.trim();
      if (!line) return null;
      let v;
      try { v = JSON.parse(line); } catch { return { ok: false, error: 'MALFORMED_JSON', line: lineNo }; }
      n++;
      if (visit(v, Buffer.byteLength(raw, 'utf8') + 1) === false) return { ok: true, entries: n, stopped: true };
      return null;
    };
    for (;;) {
      const got = fs.readSync(fd, buf, 0, buf.length, pos);
      if (got <= 0) break;
      pos += got;
      let start = 0; let i;
      while ((i = buf.indexOf(0x0a, start)) !== -1 && i < got) {
        const piece = carry ? Buffer.concat([carry, buf.subarray(start, i)]) : buf.subarray(start, i);
        carry = null;
        const r = handle(piece);
        if (r) return r;
        start = i + 1;
      }
      if (start < got) carry = carry ? Buffer.concat([carry, buf.subarray(start, got)]) : Buffer.from(buf.subarray(start, got));
    }
    const r = handle(carry || Buffer.alloc(0));   // the text after the last newline (split() always yields it)
    if (r) return r;
    return { ok: true, entries: n };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = {
  AUDIT_DOMAIN, GENESIS, HASHED_FIELDS, SUPPORTED_VERSIONS, V7_ENTRY_TYPES, v7Shape, v8Shape, mirrorDecodeString, mirrorDecodeJson,
  auditHash, declaredVersion, expectedCanonical, checkEntryHash, walkChain, parseNdjson,
  createChainWalker, createAnchorChecker, forEachNdjsonEntry,   //
  entryFromPgRow, orderPgRows, checkAnchor, isLegacyShaped, hasStoredLegacyKey,
};
