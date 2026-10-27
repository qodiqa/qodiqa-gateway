#!/usr/bin/env node
'use strict';

/**
 * Generates the audit vector families:
 *
 *   docs/protocol/vectors/audit-v8.json     AUDIT-V8-nnn     one audit entry → "ok" or the first failing rule of the entry contract
 *                                            (UNSUPPORTED_SCHEMA_VERSION, CANONICAL_MISSING, HASH_MISMATCH, CANONICAL_FIELD_MISMATCH, INVALID_ENTRY_TYPE,
 *                                            INVALID_V8_FIELD, INVALID_OUTPUT_HASH, INVALID_ENTRY_SHAPE) — AUDIT-V8-FREEZE sections 2-4, SCHEMA-V6/V7
 *   docs/protocol/vectors/audit-proof.json  AUDIT-PROOF-nnn  one `qodiqa-proof/1` document → verdict, failed checks [{id, code}], partial reasons
 *                                            (VECTORS-FORMAT section 3)
 *   docs/protocol/vectors/audit-anchor.json AUDIT-ANCHOR-nnn one line of anchors/<date>.jsonl → its statement digest or ANCHOR_LINE_MALFORMED /
 * ANCHOR_DIGEST_MISMATCH
 *
 * Entries and proofs are built by the production writers with published test seeds and a frozen clock (auditVectorFixture.js); the expected
 * verdicts are produced by the INDEPENDENT Node verifier (scripts/audit-repro/verify) and re-derived by the Python verifier
 * (scripts/audit-repro/verify/qodiqa_proof_verify.py) and, for entries, by the production entry checks. A disagreement is a defect in the
 * specification text or in one implementation — never settled by editing a vector.
 *
 *   node scripts/protocol/gen-audit-vectors.js            write the files
 *   node scripts/protocol/gen-audit-vectors.js --check    compare with the committed files (exit 1 on any difference)
 */

const fs = require('fs');
const path = require('path');
const fx = require('./auditVectorFixture');
const eb = require('../../src/core/audit/entryBuilder');
const contract = require('../audit-repro/verify/auditContract');
const { verifyProof } = require('../audit-repro/verify/proof');
const anchorTrust = require('../audit-repro/verify/anchorTrust');

const DIR = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors');
const { H, RID, clone, reseal, build } = fx;
const ISSUED = fx.T0;

// ── audit-v8: entries ────────────────────────────────────────────────────────────────────────────────────────────
const base = (over = {}) => ({ inputHash: H('a'), signature: 'sig', requestHash: H('a'), policyHash: H('b'), verificationResult: true, tenantId: 't1', ...over });
const actionCtx = { action: { tool: { server: 'srv', name: 'tool', schemaHash: H('e') }, parentRequestHash: H('f'), prevActionHash: null } };
const SPECS = {
  DECISION: () => base({ artifactId: RID, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.outputHashOf('hi'), requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2 }),
  INTENT: () => base({ artifactId: eb.lifecycleArtifactId(RID, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2 }),
  STREAM_OPENED: () => base({ artifactId: eb.lifecycleArtifactId(RID, 'STREAM_OPENED'), entryType: 'STREAM_OPENED', decision: 'ALLOW', stage: 'STREAM_OPENED', requestId: RID, executingProvider: 'local', responseId: 'r1', issuedAt: ISSUED, protocolVersion: 2 }),
  COMMIT: () => ({ artifactId: `${RID}:commit`, entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: 'sig', requestId: RID, tenantId: 't1', outputHash: H('c'), bytesDelivered: 12, completionStatus: 'COMPLETE', issuedAt: ISSUED, protocolVersion: 2 }),
  ACTION_INTENT: () => ({ artifactId: 'ar1:action_intent', entryType: 'ACTION_INTENT', decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', signature: 'sig', tenantId: 't1', agentId: 'agent-1', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), executionContext: actionCtx }),
  ACTION_COMMIT: () => ({ artifactId: 'ar1:action_commit', entryType: 'ACTION_COMMIT', decision: 'ALLOW', reason: 'ACTION_COMPLETED', signature: 'sig', tenantId: 't1', agentId: 'agent-1', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), outputHash: H('c'), completionStatus: 'COMPLETE', executionContext: actionCtx }),
  APPROVAL_REQUESTED: () => ({ artifactId: 'ap1:approval_requested', entryType: 'APPROVAL_REQUESTED', decision: 'BLOCK', reason: 'APPROVAL_REQUIRED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', policyRuleId: 'R1' } } }),
  APPROVAL_DECIDED: () => ({ artifactId: 'ap1:approval_decided', entryType: 'APPROVAL_DECIDED', decision: 'ALLOW', reason: 'APPROVED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', approverId: 'u2', decision: 'APPROVED', notBefore: null, expiresAt: 1, mfa: true } } }),
  APPROVAL_EXPIRED: () => ({ artifactId: 'ap1:approval_expired', entryType: 'APPROVAL_EXPIRED', decision: 'BLOCK', reason: 'APPROVAL_EXPIRED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1' } } }),
  KILL_SWITCH: () => ({ artifactId: 'ev1:kill_switch', entryType: 'KILL_SWITCH', decision: 'BLOCK', reason: 'KILL_SWITCH_ON', tenantId: '*', executionContext: { killSwitch: { operatorId: 'op1', scope: 'global', stateHash: H('1') } } }),
  DLP_TRANSFORM: () => ({ artifactId: `${RID}:dlp_in_1`, entryType: 'DLP_TRANSFORM', decision: 'ALLOW', reason: 'DLP_REDACT', tenantId: 't1', requestId: RID, dlp: { rules: ['email'], action: 'REDACT', inputHashBefore: H('a'), inputHashAfter: H('b') } }),
  DELEGATION_ISSUED: () => ({ artifactId: 'dg1:delegation_issued', entryType: 'DELEGATION_ISSUED', decision: 'ALLOW', reason: 'DELEGATION_ISSUED', tenantId: 't1', executionContext: { delegation: { chainHash: H('9'), depth: 1, rootAgentId: 'root', parentId: null } } }),
  DELEGATION_REVOKED: () => ({ artifactId: 'dg1:delegation_revoked', entryType: 'DELEGATION_REVOKED', decision: 'ALLOW', reason: 'DELEGATION_REVOKED', tenantId: 't1', executionContext: { delegation: { chainHash: H('9'), depth: 1, rootAgentId: 'root', parentId: null } } }),
};

function entryCases() {
  const cases = [];
  const add = (description, entry) => {
    const r = contract.checkEntryHash(entry);
    cases.push({ description, input: { entry }, ...(r.ok ? { expected: { outcome: 'ok' } } : { expectedError: { code: r.code } }) });
  };
  const v8 = {};
  const prevFlag = process.env.QODIQA_AUDIT_SCHEMA_V8;
  process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
  try {
    fx.withFixedClock(() => { let prev = 'GENESIS'; for (const [t, s] of Object.entries(SPECS)) { v8[t] = build(s(), prev); prev = v8[t].hash; } });
  } finally { if (prevFlag === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = prevFlag; }
  for (const t of Object.keys(SPECS)) add(`a valid v8 ${t} entry`, clone(v8[t]));

  // v7 and legacy shapes keep verifying (no retroactive change)
  delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  // (the v7 specs state issuedAt/protocolVersion, which a v7 writer refuses) — rebuild them without the v8 facts
  const strip = (s) => { const { issuedAt, protocolVersion, ...rest } = s; return rest; };
  const v7e = fx.withFixedClock(() => ({
    DECISION: build(strip(SPECS.DECISION()), 'GENESIS'), INTENT: build(strip(SPECS.INTENT()), 'GENESIS'), STREAM_OPENED: build(strip(SPECS.STREAM_OPENED()), 'GENESIS'),
  }));
  for (const t of ['DECISION', 'INTENT', 'STREAM_OPENED']) add(`a valid v7 ${t} entry`, clone(v7e[t]));

  const commit = v8.COMMIT; const kill = v8.KILL_SWITCH; const dec = v8.DECISION; const intent = v8.INTENT;
  // integrity failures (not re-sealed)
  add('hash changed, canonical intact', { ...clone(commit), hash: H('0') });
  add('canonical missing', (({ canonical, ...e }) => e)(clone(commit)));
  add('a hashed field changed after sealing', { ...clone(commit), bytesDelivered: 13 });
  add('schemaVersion 9 is not supported', { ...clone(commit), schemaVersion: 9 });
  add('schemaVersion as a string is not supported', { ...clone(commit), schemaVersion: '8' });
  // shape failures (re-sealed so only the shape is wrong)
  const sh = (description, e, mutate) => { const c = clone(e); mutate(c); add(description, reseal(c)); };
  sh('COMMIT bytesDelivered negative', commit, (e) => { e.bytesDelivered = -1; });
  sh('COMMIT bytesDelivered a fraction', commit, (e) => { e.bytesDelivered = 1.5; });
  sh('COMMIT completionStatus unknown', commit, (e) => { e.completionStatus = 'WHATEVER'; });
  sh('COMMIT without completionStatus', commit, (e) => { e.completionStatus = null; });
  sh('COMMIT with an unknown reason', commit, (e) => { e.reason = 'SOMETHING'; });
  sh('COMMIT with the wrong stage', commit, (e) => { e.stage = 'PROVIDER_EXECUTION'; });
  sh('COMMIT artifactId without the :commit suffix', commit, (e) => { e.artifactId = RID; });
  sh('COMMIT without an outputHash', commit, (e) => { e.outputHash = null; });
  sh('COMMIT decision BLOCK', commit, (e) => { e.decision = 'BLOCK'; });
  sh('COMMIT carrying an agentId', commit, (e) => { e.agentId = 'a1'; });
  sh('COMMIT issuedAt negative', commit, (e) => { e.issuedAt = -5; });
  sh('KILL_SWITCH with a real-looking signature', kill, (e) => { e.signature = 'abc'; });
  sh('KILL_SWITCH with verificationResult true', kill, (e) => { e.verificationResult = true; });
  sh('KILL_SWITCH without its executionContext', kill, (e) => { e.executionContext = null; });
  sh('KILL_SWITCH with a null inputHash (it states UNAVAILABLE)', kill, (e) => { e.inputHash = null; });
  sh('KILL_SWITCH with a provider', kill, (e) => { e.provider = 'local'; });
  sh('DECISION carrying an agentId', dec, (e) => { e.agentId = 'a1'; });
  sh('DECISION with an outputHash that is not 64 hex', dec, (e) => { e.outputHash = 'zz'; });
  sh('INTENT carrying an outputHash', intent, (e) => { e.outputHash = H('c'); });
  sh('INTENT with the wrong stage', intent, (e) => { e.stage = 'PROVIDER_EXECUTION'; });
  sh('a v8 entry of an unknown type', commit, (e) => { e.entryType = 'BOGUS'; });
  sh('a v7 entry of a v8-only type', clone(v7e.DECISION), (e) => { e.entryType = 'COMMIT'; });
  sh('DLP_TRANSFORM whose reason does not match its action', v8.DLP_TRANSFORM, (e) => { e.reason = 'DLP_MASK'; });
  sh('DLP_TRANSFORM with a malformed dlp object', v8.DLP_TRANSFORM, (e) => { e.dlp = { rules: [], action: 'REDACT', inputHashBefore: 'x', inputHashAfter: H('b') }; });
  sh('ACTION_INTENT with actionSeq 0', v8.ACTION_INTENT, (e) => { e.actionSeq = 0; });
  sh('ACTION_INTENT with a short actionHash', v8.ACTION_INTENT, (e) => { e.actionHash = 'abc'; });
  sh('APPROVAL_DECIDED allowed with the reason DENIED', v8.APPROVAL_DECIDED, (e) => { e.reason = 'DENIED'; });
  sh('APPROVAL_REQUESTED without an approvalRef', v8.APPROVAL_REQUESTED, (e) => { e.approvalRef = null; });
  sh('DELEGATION_ISSUED whose executionContext lacks the delegation key', v8.DELEGATION_ISSUED, (e) => { e.executionContext = { other: {} }; });
  return cases.map((c, i) => ({ id: `AUDIT-V8-${String(i + 1).padStart(3, '0')}`, ...c }));
}

// ── audit-proof: proofs ──────────────────────────────────────────────────────────────────────────────────────────
function proofCases() {
  const P = fx.buildBaseProof();
  const P7 = fx.buildBaseProof({ v8: false });
  const cases = [];
  const add = (description, doc) => {
    const r = verifyProof(doc);
    cases.push({ description, input: { proof: doc }, expected: { verdict: r.verdict, failed: r.failed.map((f) => ({ id: f.id, code: f.code })), partial: [...r.partial].sort() } });
  };
  const mut = (description, mutate, src = P) => { const d = clone(src.doc); mutate(d); add(description, d); };
  const sigFlip = (s) => { const b = Buffer.from(s, 'base64'); b[0] ^= 1; return b.toString('base64'); };

  add('a complete v8 proof (artifact, entries, transparency, checkpoint + chain path, receipt, one anchor)', clone(P.doc));
  add('a complete v7 proof (no COMMIT)', clone(P7.doc));
  mut('no artifact', (d) => { delete d.artifact; });
  mut('no transparency', (d) => { delete d.transparency; });
  mut('no checkpoint and no chain path', (d) => { delete d.checkpoint; delete d.chainPath; });
  mut('a checkpoint without a chain path', (d) => { delete d.chainPath; });
  mut('no receipt', (d) => { delete d.receipt; });
  mut('no anchors', (d) => { d.anchors = []; });
  mut('an anchor of an unknown kind', (d) => { d.anchors = [{ kind: 'carrier-pigeon', receipt: 'x' }]; });
  mut('artifact payload field changed', (d) => { d.artifact.payload.provider = 'other'; });
  mut('artifact timestamp changed', (d) => { d.artifact.timestamp += 1; });
  mut('artifact signature flipped', (d) => { d.artifact.signature = sigFlip(d.artifact.signature); });
  mut('artifact signature with its padding removed', (d) => { d.artifact.signature = d.artifact.signature.replace(/=+$/, ''); });
  mut('artifact of an unknown key', (d) => { d.artifact.publicKeyId = 'tenant1:key_v9'; });
  mut('artifact with an extra field', (d) => { d.artifact.extra = 1; });
  mut('artifact key revoked before the artifact was issued', (d) => { d.keys[0].revokedAt = d.artifact.timestamp - 1; });
  mut('artifact key revoked after the artifact was issued', (d) => { d.keys[0].revokedAt = d.artifact.timestamp + 1; });
  mut('artifact key not yet active at issue time', (d) => { d.keys[0].activatedAt = d.artifact.timestamp + 1; });
  mut('an entry field changed after sealing', (d) => { d.auditEntries[1].outputHash = H('f'); });
  mut('the entries in the wrong order', (d) => { d.auditEntries.reverse(); });
  mut('no DECISION among the entries', (d) => { d.auditEntries = d.auditEntries.filter((e) => (e.entryType ?? 'DECISION') !== 'DECISION'); delete d.chainPath; });
  mut('no entries', (d) => { d.auditEntries = []; });
  mut('a subject that none of the entries belongs to', (d) => { d.subject.requestId = '00000000-0000-4000-8000-000000000000'; });
  add('issuedAt of the entries differs from the artifact timestamp', clone(fx.buildBaseProof({ issuedAt: fx.T0 + 1 }).doc));
  mut('the transparency leaf documents another entry', (d) => { d.transparency.leaf.payload.auditEntryHash = H('d'); });
  mut('the transparency root hash changed', (d) => { d.transparency.root.rootHash = H('e'); });
  mut('the transparency root signature replaced', (d) => { d.transparency.root.signature = Buffer.alloc(64, 1).toString('base64'); });
  mut('the transparency leaf decision changed', (d) => { d.transparency.leaf.payload.decision = 'BLOCK'; });
  mut('the transparency key is missing', (d) => { d.keys = d.keys.filter((k) => k.keyId !== fx.KEY_IDS.transparency); });
  mut('the transparency inclusion proof names another position', (d) => { d.transparency.inclusionProof.leafIndex = 1; });
  mut('the checkpoint payload changed', (d) => { d.checkpoint.payload.chainLength += 1; });
  mut('the checkpoint is signed by another key', (d) => { d.keys.find((k) => k.keyId === fx.KEY_IDS.checkpoint).publicKeySpkiB64 = fx.KEYS.other.pubB64; });
  mut('the chain path has a broken link', (d) => { d.chainPath[1].prevHash = H('0'); });
  mut('the chain path stops before the checkpoint head', (d) => { d.chainPath = d.chainPath.slice(0, -1); });
  mut('the chain path does not start at the request\'s first entry', (d) => { d.chainPath = d.chainPath.slice(1); });
  mut('a chain path entry changed after sealing', (d) => { d.chainPath[d.chainPath.length - 1].outputHash = H('f'); });
  mut('the receipt decision changed', (d) => { d.receipt.decision = 'BLOCK'; });
  mut('the receipt names another entry', (d) => { d.receipt.entryHash = H('9'); });
  mut('the receipt is for another request', (d) => { d.receipt.requestId = '11111111-1111-4111-8111-111111111111'; });
  mut('format is unknown', (d) => { d.format = 'qodiqa-proof/2'; });
  mut('no subject', (d) => { delete d.subject; });
  mut('keys is not a list', (d) => { d.keys = 'x'; });
  add('the proof is an array', []);
  add('the proof is null', null);
  return cases.map((c, i) => ({ id: `AUDIT-PROOF-${String(i + 1).padStart(3, '0')}`, ...c }));
}

// ── audit-anchor: lines of the anchors repository ─────────────────────────────────────────�
function anchorCases() {
  const cases = [];
  const st = (over = {}) => ({ v: 1, checkpointId: '0b8e6c1e-52a4-4a3b-9d8f-0123456789ab', payloadHash: H('a'), chainLength: 1500, headHash: H('b'), createdAt: '2026-10-21T00:00:00.000Z', ...over });
  const lineOf = (statement, digest) => JSON.stringify({ digest: digest === undefined ? anchorTrust.statementDigest(statement) : digest, statement });
  const ok = (description, statement, line) => { const l = line || lineOf(statement); cases.push({ description, input: { line: l }, expected: { digest: JSON.parse(l).digest } }); };
  const bad = (description, line, code) => cases.push({ description, input: { line }, expectedError: { code } });
  ok('a statement', st());
  ok('the first position', st({ chainLength: 1 }));
  ok('the largest safe integer position', st({ chainLength: 9007199254740991 }));
  ok('a creation time with milliseconds and another checkpoint id', st({ createdAt: '2026-12-31T23:59:59.999Z', checkpointId: 'cp-2' }));
  const shuffled = st(); ok('keys in another order inside the line (the digest is over the canonical form)', shuffled,
    `{"statement":{"v":1,"headHash":"${H('b')}","createdAt":"2026-10-21T00:00:00.000Z","chainLength":1500,"checkpointId":"0b8e6c1e-52a4-4a3b-9d8f-0123456789ab","payloadHash":"${H('a')}"},"digest":"${anchorTrust.statementDigest(shuffled)}"}`);
  const flip = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);
  bad('the digest of another statement', lineOf(st(), flip(anchorTrust.statementDigest(st()))), 'ANCHOR_DIGEST_MISMATCH');
  bad('a statement edited after the digest was taken', lineOf(st({ chainLength: 1501 }), anchorTrust.statementDigest(st())), 'ANCHOR_DIGEST_MISMATCH');
  bad('no digest', JSON.stringify({ statement: st() }), 'ANCHOR_DIGEST_MISMATCH');
  bad('an extra statement field', lineOf({ ...st(), note: 'x' }), 'ANCHOR_LINE_MALFORMED');
  const missing = st(); delete missing.headHash; bad('a missing statement field', lineOf(missing, H('0')), 'ANCHOR_LINE_MALFORMED');
  bad('statement version 2', lineOf(st({ v: 2 })), 'ANCHOR_LINE_MALFORMED');
  bad('an uppercase payload hash', lineOf(st({ payloadHash: H('a').toUpperCase().replace(/A/g, 'A') })), 'ANCHOR_LINE_MALFORMED');
  bad('a short head hash', lineOf(st({ headHash: 'abc' })), 'ANCHOR_LINE_MALFORMED');
  bad('position zero', lineOf(st({ chainLength: 0 })), 'ANCHOR_LINE_MALFORMED');
  bad('a fractional position', lineOf(st({ chainLength: 1.5 })), 'ANCHOR_LINE_MALFORMED');
  bad('a position beyond the largest safe integer', '{"digest":"' + H('0') + '","statement":{"v":1,"checkpointId":"c","payloadHash":"' + H('a') + '","chainLength":9007199254740993,"headHash":"' + H('b') + '","createdAt":"t"}}', 'ANCHOR_LINE_MALFORMED');
  bad('a numeric checkpoint id', lineOf(st({ checkpointId: 7 })), 'ANCHOR_LINE_MALFORMED');
  bad('a creation time that is not text', lineOf(st({ createdAt: 1790000000000 })), 'ANCHOR_LINE_MALFORMED');
  bad('a creation time with a UTC offset instead of Z', lineOf(st({ createdAt: '2026-10-21T00:00:00.000+00:00' })), 'ANCHOR_LINE_MALFORMED');
  bad('a creation time that is not a date', lineOf(st({ createdAt: 'yesterday' })), 'ANCHOR_LINE_MALFORMED');
  bad('a line ending with a carriage return', lineOf(st()) + String.fromCharCode(13), 'ANCHOR_LINE_MALFORMED');
  bad('a checkpoint id with a line separator', lineOf(st({ checkpointId: 'c' + String.fromCharCode(0x2028) + 'd' })), 'ANCHOR_LINE_MALFORMED');
  bad('not JSON', '{"digest":', 'ANCHOR_LINE_MALFORMED');
  bad('a JSON array', '[]', 'ANCHOR_LINE_MALFORMED');
  bad('the statement is null', '{"digest":"x","statement":null}', 'ANCHOR_LINE_MALFORMED');
  return cases.map((c, i) => ({ id: `AUDIT-ANCHOR-${String(i + 1).padStart(3, '0')}`, ...c }));
}

const HEADER = (family, description, schema) => ({ format: 'qodiqa-vectors/1', family, generatedBy: 'scripts/protocol/gen-audit-vectors.js', specVersion: 'v2-freeze-1', mode: 'verify', nowMs: 0, inputSchema: { type: 'object', description, ...schema } });
function files() {
  return {
    'audit-v8.json': { ...HEADER('audit-v8', 'one audit entry; the verdict is expected.outcome "ok" or expectedError.code, the first failing rule of: UNSUPPORTED_SCHEMA_VERSION, CANONICAL_MISSING, HASH_MISMATCH, CANONICAL_FIELD_MISMATCH, INVALID_ENTRY_TYPE, INVALID_V8_FIELD, INVALID_OUTPUT_HASH, INVALID_ENTRY_SHAPE', { required: ['entry'], properties: { entry: { description: 'an audit entry as stored (canonical, hash and every field)' } } }), cases: entryCases() },
    'audit-proof.json': { ...HEADER('audit-proof', 'one proof document; expected.verdict is VALID, VALID_PARTIAL or INVALID, expected.failed the failed checks as {id, code} in check order, expected.partial the sorted reasons that lowered the verdict (docs/protocol/VECTORS-FORMAT.md section 3)', { required: ['proof'], properties: { proof: { description: 'any JSON value: the proof under test' } } }), cases: proofCases() },
    'audit-anchor.json': { ...HEADER('audit-anchor', 'one line of anchors/<date>.jsonl; expected.digest is the SHA-256 (hex) of "QODIQA::EXTERNAL_ANCHOR::V1" followed by the canonical form of the statement, or expectedError.code is ANCHOR_LINE_MALFORMED / ANCHOR_DIGEST_MISMATCH (docs/protocol/VECTORS-FORMAT.md section 3.2)', { required: ['line'], properties: { line: { type: 'string', description: 'the raw text of one JSONL line' } } }), cases: anchorCases() },
  };
}

const render = (o) => `${JSON.stringify(o, null, 1)}\n`;
const out = files();
if (process.argv.includes('--check')) {
  const drift = [];
  for (const [name, f] of Object.entries(out)) {
    const p = path.join(DIR, name);
    if (!fs.existsSync(p) || fs.readFileSync(p, 'utf8') !== render(f)) drift.push(name);
  }
  process.stdout.write(`${JSON.stringify({ ok: drift.length === 0, drift })}\n`);
  if (drift.length) { process.stderr.write('[audit-vectors] DRIFT: run `npm run protocol:vectors` and review the diff.\n'); process.exit(1); }
} else {
  for (const [name, f] of Object.entries(out)) fs.writeFileSync(path.join(DIR, name), render(f));
  process.stdout.write(`${JSON.stringify({ wrote: Object.keys(out), cases: Object.fromEntries(Object.entries(out).map(([n, f]) => [n, f.cases.length])) })}\n`);
}
module.exports = { files };
