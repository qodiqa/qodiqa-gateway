#!/usr/bin/env node
'use strict';

/**
 * Generates the approval-statement vectors (docs/protocol/vectors/approval.json, APPROVAL-nnn) from the PRODUCTION implementation
 * (src/core/approvals/approvalToken.js, V2-FREEZE section 1 `QODIQA::APPROVAL::V1`).
 *
 * Each case is an envelope, the verification time and (optionally) what the statement is presented for ("expect": the action hash, tenant, agent, session, seq, approval id). The
 * verdict is {ok:true, digest} or {ok:false, reason, detail}. `detail` is one of a small closed vocabulary - every way the payload or the envelope can be malformed is "shape".
 * Chains are signed with PUBLISHED test seeds and fixed identifiers/timestamps, so the file is byte-for-byte reproducible. Two independent verifiers (verify-approval-vectors.js,
 * verify_approval_vectors.py - no QODIQA import, own JCS-P1, the Python one with its own Ed25519) re-derive every verdict. A disagreement is a defect in the specification, the
 * implementation or a verifier - never settled by editing a vector.
 *
 *   node scripts/protocol/gen-approval-vectors.js            write the file
 *   node scripts/protocol/gen-approval-vectors.js --check    regenerate in memory and compare with the committed file (exit 1 on any difference)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tok = require('../../src/core/approvals/approvalToken');
const { sign } = require('../../src/infra/crypto/ed25519');

const FILE = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'approval.json');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const seedOf = (label) => crypto.createHash('sha256').update(`QODIQA published approval test seed: ${label}`, 'utf8').digest();
const privOf = (seed) => Buffer.concat([PKCS8_PREFIX, seed]);
const pubOf = (seed) => crypto.createPublicKey({ key: privOf(seed), format: 'der', type: 'pkcs8' }).export({ format: 'der', type: 'spki' });
const KEYS = [{ publicKeyId: 'tenant-a:key_v1', clientId: 'tenant-a', seed: seedOf('tenant-a') }, { publicKeyId: 'tenant-b:key_v1', clientId: 'tenant-b', seed: seedOf('tenant-b') }];
const KA = KEYS[0]; const KB = KEYS[1];
const NOW = 1_800_000_000_000;
const MIN = 60_000;
const H = (c) => c.repeat(64);
const U = (n) => `${String(n).padStart(8, '0')}-0000-4000-8000-${String(n).padStart(12, '0')}`;
const AGENT = U(1); const SESSION = U(2); const APPROVAL = U(3);

const payload = (o = {}) => ({ v: 1, kind: 'approval', approvalId: APPROVAL, tenantId: 'tenant-a', actionHash: H('a'), agentId: AGENT, sessionId: SESSION, seq: 3, requesterId: 'identity:i-1', approverId: 'bob@example.com',
  decision: 'APPROVED', notBefore: NOW - MIN, expiresAt: NOW + 9 * MIN, mfa: 'step-up', policyRuleId: 'tool:requiresApproval', ...o });
/** sign ANY payload (including malformed ones) with the production digest and signing primitive */
function rawSign(p, { key = KA, signWith, timestamp = NOW - MIN, expiry } = {}) {
  const fields = { expiry: expiry === undefined ? p.expiresAt : expiry, payload: p, publicKeyId: key.publicKeyId, timestamp };
  return { expiry: fields.expiry, payload: p, publicKeyId: key.publicKeyId, signature: sign(tok.envelopeDigest(fields), privOf((signWith || key).seed)), timestamp };
}
const good = (o, f) => rawSign(payload(o), f);
const clone = (x) => JSON.parse(JSON.stringify(x));
const mut = (e, f) => { const c = clone(e); f(c); return c; };

const SEMANTIC = new Set(['signature', 'tenant', 'not for this actionHash', 'not for this tenantId', 'not for this agentId', 'not for this sessionId', 'not for this seq', 'not for this approvalId',
  'the approver is the requester', 'denied', 'decided in the future', 'not yet valid']);
const detailKind = (d) => (d === undefined ? undefined : (SEMANTIC.has(d) ? d : 'shape'));

function build() {
  const cases = [];
  const resolveKey = (id) => { const k = KEYS.find((x) => x.publicKeyId === id); return k ? { found: true, pubDer: pubOf(k.seed), clientId: k.clientId } : { found: false }; };
  const add = (description, envelope, { now = NOW, expect } = {}) => {
    const v = tok.verifyApproval(clone(envelope), { now, resolveKey, ...(expect ? { expect } : {}) });
    const expected = v.ok ? { ok: true, digest: v.digest } : { ok: false, reason: v.reason, ...(v.detail ? { detail: detailKind(v.detail) } : {}) };
    cases.push({ id: `APPROVAL-${String(cases.length + 1).padStart(3, '0')}`, description, input: { envelope: clone(envelope), now, ...(expect ? { expect } : {}) }, expected });
  };
  const e0 = good();
  const exp0 = { actionHash: H('a'), tenantId: 'tenant-a', agentId: AGENT, sessionId: SESSION, seq: 3, approvalId: APPROVAL };

  add('a valid approval', e0);
  add('a valid approval, presented for exactly this action', e0, { expect: exp0 });
  add('valid at the first millisecond of its window', e0, { now: NOW - MIN });
  add('valid one millisecond before it expires', e0, { now: NOW + 9 * MIN - 1 });
  add('a valid approval with a window that starts later (not yet valid before)', good({ notBefore: NOW + MIN }), { now: NOW });
  add('the same approval once its window has opened', good({ notBefore: NOW + MIN }), { now: NOW + MIN });
  add('a different approver and requester', good({ approverId: 'carol', requesterId: 'identity:i-2' }));

  add('expired at the moment of expiry', e0, { now: NOW + 9 * MIN });
  add('expired long ago', e0, { now: NOW + 3_600_000 });
  add('decided in the future', rawSign(payload({ expiresAt: NOW + 20 * MIN }), { timestamp: NOW + 10 * MIN }), { now: NOW });
  add('denied (a signed refusal is evidence, not an approval)', good({ decision: 'DENIED' }));

  add('presented for another actionHash', e0, { expect: { ...exp0, actionHash: H('b') } });
  add('presented for another tenant', e0, { expect: { ...exp0, tenantId: 'tenant-b' } });
  add('presented for another agent', e0, { expect: { ...exp0, agentId: U(9) } });
  add('presented for another session', e0, { expect: { ...exp0, sessionId: U(9) } });
  add('presented for another position in the session', e0, { expect: { ...exp0, seq: 4 } });
  add('presented for another approval id', e0, { expect: { ...exp0, approvalId: U(9) } });

  add('payload altered after signing: the action hash', mut(e0, (c) => { c.payload.actionHash = H('b'); }));
  add('payload altered after signing: the approver', mut(e0, (c) => { c.payload.approverId = 'mallory'; }));
  add('payload altered after signing: the window extended', mut(e0, (c) => { c.payload.expiresAt += MIN; c.expiry += MIN; }));
  add('timestamp altered after signing', mut(e0, (c) => { c.timestamp += 1; }));
  add('signature altered', mut(e0, (c) => { c.signature = `${c.signature.slice(0, 10)}${c.signature[10] === 'A' ? 'B' : 'A'}${c.signature.slice(11)}`; }));
  add('signature with non-canonical encoding (no padding)', mut(e0, (c) => { c.signature = c.signature.replace(/=+$/, ''); }));
  add('signed by a key that is not the tenant key', good({}, { signWith: { seed: seedOf('stranger') } }));
  add('a key id nobody knows', mut(e0, (c) => { c.publicKeyId = 'tenant-z:key_v1'; }));
  add('signed with another tenant\'s key for this tenant', rawSign(payload(), { key: KB }));
  add('approved by the requester (approver equals requester)', rawSign(payload({ approverId: 'identity:i-1' })));

  add('envelope with an extra member', mut(e0, (c) => { c.note = 'x'; }));
  add('payload with an extra member', rawSign({ ...payload(), note: 'x' }));
  add('payload missing a member', rawSign((() => { const p = payload(); delete p.policyRuleId; return p; })()));
  add('wrong kind', rawSign(payload({ kind: 'delegation' })));
  add('wrong version', rawSign(payload({ v: 2 })));
  add('seq 0', rawSign(payload({ seq: 0 })));
  add('seq as a string', rawSign(payload({ seq: '3' })));
  add('action hash in upper case', rawSign(payload({ actionHash: H('A') })));
  add('agent id that is not a UUID v4', rawSign(payload({ agentId: 'agent-1' })));
  add('decision neither APPROVED nor DENIED', rawSign(payload({ decision: 'MAYBE' })));
  add('mfa other than step-up', rawSign(payload({ mfa: 'none' })));
  add('window that ends before it starts', rawSign(payload({ notBefore: NOW, expiresAt: NOW - 1 })));
  add('empty approver', rawSign(payload({ approverId: '' })));
  add('expiry of the envelope different from payload.expiresAt', rawSign(payload(), { expiry: NOW + 10 * MIN }));

  const v = {
    format: 'qodiqa-vectors/1', family: 'approval', spec: 'src/core/approvals/approvalToken.js (QODIQA::APPROVAL::V1)', specVersion: 'v2-freeze-1', generatedBy: 'scripts/protocol/gen-approval-vectors.js',
    domain: tok.APPROVAL_DOMAIN,
    keys: KEYS.map((k) => ({ publicKeyId: k.publicKeyId, clientId: k.clientId, publicKeySpkiB64: pubOf(k.seed).toString('base64'), seedNote: 'published test seed: SHA-256("QODIQA published approval test seed: <clientId>")' })),
    cases,
  };
  v.counts = { cases: cases.length, valid: cases.filter((c) => c.expected.ok).length, refused: cases.filter((c) => !c.expected.ok).length,
    byReason: cases.reduce((a, c) => { if (!c.expected.ok) a[c.expected.reason] = (a[c.expected.reason] || 0) + 1; return a; }, {}) };
  return v;
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
if (require.main === module) {
  const text = `${JSON.stringify(build(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    const have = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : '';
    const ok = have === text;
    process.stdout.write(`${JSON.stringify({ ok, file: 'docs/protocol/vectors/approval.json', generatedSha256: sha(text), committedSha256: sha(have) })}\n`);
    if (!ok) { process.stderr.write('[approval-vectors] DRIFT: run `npm run protocol:vectors` and review the diff\n'); process.exit(1); }
  } else {
    fs.writeFileSync(FILE, text);
    process.stdout.write(`${JSON.stringify({ wrote: path.relative(process.cwd(), FILE), counts: build().counts })}\n`);
  }
}

module.exports = { build, KEYS };
