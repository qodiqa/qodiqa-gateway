'use strict';

/**
 * audit schema v7 — core contract.
 *
 *   V7-01…V7-09  entryBuilder: 28-field hash set, entryType / outputHash rules, fixed lifecycle values, artifact-id
 *                suffixes, OUTPUT domain, incremental output hasher, executionContext canonicalization (no silent
 *                stringification), shape violations, detail ordering
 *   LC-01…LC-08  lifecycle rules: MISSING_INTENT only in GENESIS-start walks, INTENT_BEFORE_START warning in bounded
 *                walks, ORPHAN_INTENT, SCHEMA_DOWNGRADE, mixed v6 → v7 history, disk scan + in-memory + chunked walkers
 *   ST-01        statistics count DECISION entries only
 * PS-01…PS-03 pseudonymization of consentProvenance.subject / callerContext.callerId on append (explicit
 *                test-only pseudonym stand-in; the fail-closed no-PostgreSQL path is pseudonymFailClosed.test.js)
 */

jest.mock('../../../infra/postgres/pg-audit-backend', () => ({ persistEntry: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const eb = require('../entryBuilder');
const { createLifecycleTracker } = require('../v7Lifecycle');
const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');
const { expectedPseudonym } = require('../../../../test/helpers/subjectPseudonymMock');

const H = (c) => c.repeat(64);
const RID = '11111111-1111-4111-8111-111111111111';
const base = (over = {}) => ({ inputHash: H('a'), signature: 'sig', requestHash: H('a'), policyHash: H('b'), verificationResult: true, tenantId: 't1', ...over });

function chainOf(specs, prev = 'GENESIS') {
  const out = [];
  for (const s of specs) { const e = eb.buildEntry(eb.normalizeFields(base(s)), prev); out.push(JSON.parse(JSON.stringify(e))); prev = e.hash; }
  return out;
}
const intent = (rid = RID, over = {}) => ({ artifactId: eb.lifecycleArtifactId(rid, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', outputHash: null, requestId: rid, executingProvider: 'local', ...over });
const streamOpened = (rid = RID, over = {}) => ({ artifactId: eb.lifecycleArtifactId(rid, 'STREAM_OPENED'), entryType: 'STREAM_OPENED', decision: 'ALLOW', stage: 'STREAM_OPENED', outputHash: null, requestId: rid, executingProvider: 'local', responseId: 'stream-1', ...over });
const decision = (rid = RID, over = {}) => ({ artifactId: rid, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.outputHashOf('hi'), requestId: rid, executingProvider: 'local', ...over });
/** a genuine schemaVersion 6 entry, sealed exactly as the pre-v7 builder did */
function v6Entry(prev, id = 'v6-' + crypto.randomUUID()) {
  const e = { artifactId: id, decision: 'ALLOW', inputHash: H('a'), policyHash: H('b'), prevHash: prev, requestHash: H('a'), signature: 'sig', timestamp: new Date().toISOString(), verificationResult: true, publicKeyId: null, schemaVersion: 6, consentProvenance: null, policyDecision: null, callerContext: null, provider: null, model: null, stage: null, reason: null, semantic: null, tokenUsage: null, responseId: null, highResTime: '1' };
  const core = {}; for (const f of eb.CORE_HASH_FIELDS_V6) core[f] = e[f];
  const canonical = sortedJSON(core);
  return { ...e, canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') };
}

describe('V7 — entryBuilder contract', () => {
  test('V7-01 v7 is current; V7 = V6 + the seven approved fields; every v7 entry hashes exactly 28 fields', () => {
    expect(eb.CURRENT_SCHEMA_VERSION).toBe(7);
    expect(eb.SUPPORTED_SCHEMA_VERSIONS).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);   // 8 = audit v8; the writer stays at 7 until QODIQA_AUDIT_SCHEMA_V8
    expect(eb.CORE_HASH_FIELDS_V7).toEqual([...eb.CORE_HASH_FIELDS_V6, 'entryType', 'outputHash', 'tenantId', 'requestId', 'organizationId', 'executionContext', 'executingProvider']);
    const [e] = chainOf([decision()]);
    expect(Object.keys(JSON.parse(e.canonical)).sort()).toEqual([...eb.CORE_HASH_FIELDS_V7].sort());
    for (const f of ['nonce', 'traceId', 'highResTime']) expect(JSON.parse(e.canonical)).not.toHaveProperty(f);
  });

  test('V7-02 entryType defaults to DECISION; an ALLOW DECISION must state outputHash; a BLOCK defaults to the empty-bytes hash', () => {
    expect(() => eb.normalizeFields(base({ artifactId: 'a', decision: 'ALLOW' }))).toThrow(/^invalid_outputHash/);
    const blk = eb.normalizeFields(base({ artifactId: 'b', decision: 'BLOCK' }));
    expect(blk.entryType).toBe('DECISION');
    expect(blk.outputHash).toBe(eb.EMPTY_OUTPUT_HASH);
    expect(() => eb.normalizeFields(base({ artifactId: 'c', decision: 'ALLOW', outputHash: 'not-hex' }))).toThrow(/^invalid_outputHash/);
    expect(() => eb.normalizeFields(base({ artifactId: 'c', decision: 'ALLOW', outputHash: H('A') }))).toThrow(/^invalid_outputHash/); // lower-case hex only
    expect(() => eb.normalizeFields(base({ artifactId: 'd', decision: 'ALLOW', outputHash: H('a'), entryType: 'BOGUS' }))).toThrow(/^invalid_entryType/);
  });

  test('V7-03 R-5: outputHash = SHA-256("QODIQA::OUTPUT::V1" ‖ UTF-8 content); empty → hash of the empty byte string', () => {
    expect(ARTIFACT_DOMAINS.OUTPUT).toBe('QODIQA::OUTPUT::V1');
    const content = 'héllo 😀 world';
    const manual = crypto.createHash('sha256').update('QODIQA::OUTPUT::V1', 'utf8').update(content, 'utf8').digest('hex');
    expect(eb.outputHashOf(content)).toBe(manual);
    expect(eb.EMPTY_OUTPUT_HASH).toBe(crypto.createHash('sha256').update('QODIQA::OUTPUT::V1', 'utf8').digest('hex'));
    expect(eb.outputHashOf(content)).not.toBe(domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, content).toString('hex'));
    expect(() => eb.outputHashOf({ output: content })).toThrow(TypeError); // never the envelope
  });

  test('V7-04 the incremental stream hasher equals outputHashOf(concatenation), surrogate pairs split across chunks included', () => {
    const cases = [[], [''], ['a', 'b'], ['\ud83d', '\ude00'], ['x\ud83d', '\ude00y', 'z'], ['\ude00', 'q'], ['é', '', 'ü\ud800']];
    for (const c of cases) {
      const h = eb.createOutputHasher(); c.forEach((x) => h.update(x));
      expect({ c, h: h.digest() }).toEqual({ c, h: eb.outputHashOf(c.join('')) });
    }
    const h = eb.createOutputHasher(); h.digest();
    expect(() => h.update('late')).toThrow(/after digest/);
  });

  test('V7-05 lifecycle entries take the fixed approved values and suffixed artifact ids (R-8 / R-8a / R-9)', () => {
    expect(eb.LIFECYCLE_FIXED).toEqual({ INTENT: { decision: 'ALLOW', stage: 'PROVIDER_DISPATCH' }, STREAM_OPENED: { decision: 'ALLOW', stage: 'STREAM_OPENED' } });
    expect(eb.lifecycleArtifactId(RID, 'INTENT')).toBe(`${RID}:intent`);
    expect(eb.lifecycleArtifactId(RID, 'STREAM_OPENED')).toBe(`${RID}:stream_opened`);
    expect(() => eb.lifecycleArtifactId(RID, 'DECISION')).toThrow();
    const ok = eb.normalizeFields(base(intent()));
    expect(ok).toMatchObject({ entryType: 'INTENT', outputHash: null });
    expect(() => eb.normalizeFields(base(intent(RID, { outputHash: H('a') })))).toThrow(/^invalid_/);
    expect(() => eb.normalizeFields(base(intent(RID, { decision: 'BLOCK' })))).toThrow(/^invalid_/);
    expect(() => eb.normalizeFields(base(intent(RID, { stage: 'PROVIDER_EXECUTION' })))).toThrow(/^invalid_/);
    expect(() => eb.normalizeFields(base(streamOpened(RID, { stage: 'PROVIDER_DISPATCH' })))).toThrow(/^invalid_/);
  });

  test('V7-06 R-6: executionContext is hashed whole; undefined members → null; non-JSON values are REFUSED, never stringified', () => {
    const [e] = chainOf([decision(RID, { executionContext: { b: 2, a: { y: undefined, x: [1, 'two', null] } } })]);
    expect(JSON.parse(e.canonical).executionContext).toEqual({ a: { x: [1, 'two', null], y: null }, b: 2 });
    expect(e.executionContext).toEqual({ a: { x: [1, 'two', null], y: null }, b: 2 });   // stored == hashed form
    const cyc = {}; cyc.self = cyc;
    for (const bad of [{ d: new Date() }, { n: NaN }, { i: Infinity }, { f() {} }, cyc, { big: 10n }, new (class X { constructor() { this.a = 1; } })()]) {
      let err = null;
      try { eb.normalizeFields(base(decision(RID, { executionContext: bad }))); } catch (e2) { err = e2; }
      expect(err).not.toBeNull();
      expect(err.message).toMatch(/^invalid_executionContext/);
    }
  });

  test('V7-07 a self-consistently sealed v7 entry that breaks the shape rules does not verify, and reports the shape detail', () => {
    const [good] = chainOf([decision()]);
    const reseal = (e) => { const core = {}; for (const f of eb.CORE_HASH_FIELDS_V7) core[f] = e[f]; const canonical = sortedJSON(core); return { ...e, canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') }; };
    const cases = [
      [{ entryType: 'WHATEVER' }, 'INVALID_ENTRY_TYPE'],
      [{ outputHash: null }, 'INVALID_OUTPUT_HASH'],
      [{ entryType: 'INTENT' }, 'INVALID_ENTRY_SHAPE'],                                     // INTENT with an outputHash
      [{ entryType: 'INTENT', outputHash: null, stage: 'PROVIDER_EXECUTION' }, 'INVALID_ENTRY_SHAPE'],
      [{ entryType: 'STREAM_OPENED', outputHash: null, stage: 'STREAM_OPENED', decision: 'BLOCK' }, 'INVALID_ENTRY_SHAPE'],
    ];
    for (const [over, code] of cases) {
      const bad = reseal({ ...good, ...over });
      expect({ over, ok: eb.verifyCanonicalHash(bad), shape: eb.v7ShapeViolation(bad), detail: eb.v7IntegrityDetail(bad) }).toEqual({ over, ok: false, shape: code, detail: code });
    }
  });

  test('V7-08 a field/canonical mismatch is reported without a shape detail (same order as the independent verifier)', () => {
    const [good] = chainOf([decision()]);
    const tampered = { ...good, entryType: 'NOT_A_TYPE' };              // not resealed
    expect(eb.verifyCanonicalHash(tampered)).toBe(false);
    expect(eb.v7IntegrityDetail(tampered)).toBeNull();
    expect(eb.entryTypeOf(tampered)).toBe('NOT_A_TYPE');
    expect(eb.entryTypeOf({ schemaVersion: 6, entryType: 'INTENT' })).toBe('DECISION');   // pre-v7 entries are decisions
  });

  test('V7-09 every v7 identifier, executionContext and executingProvider is tamper-evident', () => {
    const [e] = chainOf([decision(RID, { organizationId: 'org', executionContext: { stage: 'X' } })]);
    for (const [f, v] of [['entryType', 'INTENT'], ['outputHash', H('c')], ['tenantId', 't2'], ['requestId', 'r2'], ['organizationId', 'o2'], ['executionContext', { stage: 'Y' }], ['executingProvider', 'other']]) {
      expect({ f, ok: eb.verifyCanonicalHash({ ...e, [f]: v }) }).toEqual({ f, ok: false });
    }
  });
});

describe('LC — lifecycle rules (R-2 / R-17, C-26)', () => {
  test('LC-01 tracker: DECISION with a provider and no INTENT → MISSING_INTENT when complete, INTENT_BEFORE_START warning when bounded', () => {
    const [d] = chainOf([decision()]);
    const complete = createLifecycleTracker({ lifecycleComplete: true });
    expect(complete.step(d)).toEqual({ detail: 'MISSING_INTENT' });
    const bounded = createLifecycleTracker({ lifecycleComplete: false });
    expect(bounded.step(d)).toBeNull();
    expect(bounded.finish()).toEqual([{ code: 'INTENT_BEFORE_START', severity: 'WARNING', count: 1, sample: [{ artifactId: RID, requestId: RID }] }]);
  });

  test('LC-02 tracker: a DECISION with no provider call needs no INTENT; INTENT / STREAM_OPENED close on their DECISION; leftovers are ORPHAN_INTENT', () => {
    const t = createLifecycleTracker({ lifecycleComplete: true });
    const c = chainOf([decision('r0', { decision: 'BLOCK', outputHash: undefined, executingProvider: null }), intent('r1'), streamOpened('r1'), decision('r1'), intent('r2')]);
    for (const e of c) expect(t.step(e)).toBeNull();
    expect(t.finish()).toEqual([{ code: 'ORPHAN_INTENT', severity: 'WARNING', count: 1, sample: [{ requestId: 'r2', entryType: 'INTENT' }] }]);
  });

  test('LC-03 tracker: an older version after the first v7 entry is SCHEMA_DOWNGRADE; v6 → v7 (an upgrade) is fine', () => {
    const t = createLifecycleTracker({ lifecycleComplete: true });
    const [d] = chainOf([decision('r', { executingProvider: null })]);
    expect(t.step(v6Entry('GENESIS'))).toBeNull();
    expect(t.step(d)).toBeNull();
    expect(t.step(v6Entry(d.hash))).toEqual({ detail: 'SCHEMA_DOWNGRADE' });
  });

  test('LC-04 in-memory walk from GENESIS: complete lifecycle verifies with lifecycleComplete:true and no warnings', () => {
    const audit = freshAudit();
    const c = chainOf([intent(), decision()]);
    expect(audit.verifyAuditChainDetailed(c)).toMatchObject({ valid: true, lifecycleComplete: true, warnings: [], entriesVerified: 2 });
  });

  test('LC-05 in-memory walk from GENESIS: a provider DECISION without its INTENT fails AUDIT_CHAIN_TAMPERED / MISSING_INTENT at its index', () => {
    const audit = freshAudit();
    const c = chainOf([decision('r0', { executingProvider: null }), decision()]);
    expect(audit.verifyAuditChainDetailed(c)).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'MISSING_INTENT', offendingIndex: 1 });
  });

  test('LC-06 bounded walk (starts after GENESIS): the same gap is the INTENT_BEFORE_START WARNING — never a failure (C-26)', async () => {
    const audit = freshAudit();
    const c = chainOf([intent(), decision()]);
    const suffix = c.slice(1);
    const w = audit.verifyAuditChainDetailed(suffix, c[0].hash);
    expect(w).toMatchObject({ valid: true, lifecycleComplete: false, entriesVerified: 1 });
    expect(w.warnings.map((x) => x.code)).toEqual(['INTENT_BEFORE_START']);
    const chunked = await audit.verifyAuditChainDetailedChunked(suffix, c[0].hash);
    expect(chunked).toMatchObject({ valid: true, lifecycleComplete: false });
    expect(chunked.warnings.map((x) => x.code)).toEqual(['INTENT_BEFORE_START']);
  });

  test('LC-07 mixed v6 → v7 history verifies; a v6 entry after v7 is SCHEMA_DOWNGRADE (R-2)', () => {
    const audit = freshAudit();
    const a = v6Entry('GENESIS');
    const b = chainOf([intent(), decision()], a.hash);
    expect(audit.verifyAuditChainDetailed([a, ...b])).toMatchObject({ valid: true, entriesVerified: 3 });
    const down = v6Entry(b[1].hash);
    expect(audit.verifyAuditChainDetailed([a, ...b, down])).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'SCHEMA_DOWNGRADE', offendingIndex: 3 });
  });

  test('LC-08 disk scan (full-chain verifier) applies the same rules: MISSING_INTENT from GENESIS; ORPHAN_INTENT is a warning only', () => {
    const { audit, log } = freshAuditOnDisk();
    const missing = chainOf([decision()]);
    fs.writeFileSync(log, missing.map((e) => JSON.stringify(e)).join('\n') + '\n');
    const d1 = audit.verifyFullChainFromDisk();
    expect(d1.walkResult).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED' });
    const orphan = chainOf([intent('r9')]);
    fs.writeFileSync(log, orphan.map((e) => JSON.stringify(e)).join('\n') + '\n');
    const d2 = audit.verifyFullChainFromDisk();
    expect(d2.walkResult.valid).toBe(true);
    expect(d2.lifecycleComplete).toBe(true);
    expect(d2.warnings.map((x) => x.code)).toEqual(['ORPHAN_INTENT']);
  });
});

describe('ST — statistics', () => {
  test('ST-01 allow/block counters count DECISION entries only; structural counts still count every entry', async () => {
    const audit = freshAudit();
    await audit.append({ ...base(intent('s1')) });
    await audit.append({ ...base(decision('s1')) });
    await audit.append({ ...base(intent('s2')) });
    await audit.append({ ...base(decision('s2', { decision: 'BLOCK', outputHash: undefined })) });
    const s = audit.getChainStats();
    expect(s).toMatchObject({ allowCount: 1, blockCount: 1, modernLength: 4, chainLength: 4 });
  });
});

describe('PS — pseudonymization on append (R-12 / R-13 / R-15)', () => {
  test('PS-01 consentProvenance.subject and callerContext.callerId are replaced by their pseudonyms before hashing; no raw id remains', async () => {
    const { audit, pseudonymFor } = freshAuditOnDisk();
    const e = await audit.append({ ...base(decision('p1')), consentProvenance: { consentId: 'c1', subject: 'alice@example.test' }, callerContext: { callerId: 'identity-bob', callerName: 'ci' } });
    expect(e.consentProvenance.subject).toBe(expectedPseudonym('t1', 'alice@example.test'));
    expect(e.callerContext.callerId).toBe(expectedPseudonym('t1', 'identity-bob'));
    expect(e.callerContext.callerName).toBe('ci');
    expect(JSON.stringify(e)).not.toMatch(/alice@example\.test|identity-bob/);
    expect(eb.verifyCanonicalHash(e)).toBe(true);
    expect(pseudonymFor).toHaveBeenCalledTimes(2);                       // one lookup per identity, no cache (R-15)
  });

  test('PS-02 already-pseudonymized values pass unchanged (idempotent); no identity → no lookup at all', async () => {
    const { audit, pseudonymFor } = freshAuditOnDisk();
    const p = expectedPseudonym('t1', 'carol');
    const e = await audit.append({ ...base(decision('p2')), callerContext: { callerId: p } });
    expect(e.callerContext.callerId).toBe(p);
    pseudonymFor.mockClear();
    await audit.append({ ...base(decision('p3')) });
    expect(pseudonymFor).not.toHaveBeenCalled();
  });

  test('PS-03 a pseudonym lookup failure refuses the append (nothing written) — never a raw-identity fallback', async () => {
    const { audit, pseudonymFor } = freshAuditOnDisk();
    const before = audit.getChainStats().modernLength;
    pseudonymFor.mockRejectedValueOnce(Object.assign(new Error('subject pseudonyms require PostgreSQL'), { code: 'SUBJECT_PSEUDONYM_UNAVAILABLE' }));
    await expect(audit.appendMandatory({ ...base(decision('p4')), callerContext: { callerId: 'dave' } }, { stage: 'ALLOW', maxRetries: 2, retryDelayMs: 1 }))
      .rejects.toMatchObject({ code: 'SUBJECT_PSEUDONYM_UNAVAILABLE', message: expect.stringMatching(/^subject_pseudonym_unavailable/) });
    expect(pseudonymFor).toHaveBeenCalledTimes(1);                       // non-retryable: no retry burned on it
    expect(audit.getChainStats().modernLength).toBe(before);
  });
});

// ── harness ─────────────────────────────────────────────────────────────────
let tmpDirs = [];
afterAll(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });   // this suite's own temp dirs
function freshAuditOnDisk() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w7v7-'));
  tmpDirs.push(dir);
  const log = path.join(dir, 'audit.log');
  const saved = process.env.QODIQA_AUDIT_LOG;
  process.env.QODIQA_AUDIT_LOG = log;
  let audit; let pseudonymFor;
  try {
    jest.isolateModules(() => { audit = require('../audit-log'); pseudonymFor = require('../../dsr/subjectPseudonym').pseudonymFor; });
  } finally { if (saved === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved; }
  return { audit, log, pseudonymFor };
}
function freshAudit() { return freshAuditOnDisk().audit; }
