#!/usr/bin/env node
'use strict';

/**
 * INDEPENDENT verifier for the approval-statement vectors (docs/protocol/vectors/approval.json, APPROVAL-nnn).
 *
 * Imports NOTHING from src/ or services/: only node:crypto/fs/path and the independent JCS-P1 implementation of verify-v2-vectors.js. The rules of
 * src/core/approvals/approvalToken.js are re-implemented here from the specification text (its header). The Python counterpart is verify_approval_vectors.py.
 *
 *   node scripts/protocol/verify-approval-vectors.js [file.json]     exit 1 on any mismatch
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseJcsP1 } = require('./verify-v2-vectors');

const DOMAIN = 'QODIQA::APPROVAL::V1';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;
const ENVELOPE_KEYS = 'expiry,payload,publicKeyId,signature,timestamp';
const PAYLOAD_KEYS = 'actionHash,agentId,approvalId,approverId,decision,expiresAt,kind,mfa,notBefore,policyRuleId,requesterId,seq,sessionId,tenantId,v';
const MAX_SKEW = 5 * 60_000;
const SAFE = Number.MAX_SAFE_INTEGER;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const idStr = (v) => typeof v === 'string' && v.length >= 1 && v.length <= 256 && ![...v].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127);

function shapeOk(p) {
  if (!isObj(p) || Object.keys(p).sort().join(',') !== PAYLOAD_KEYS) return false;
  if (p.v !== 1 || p.kind !== 'approval') return false;
  if (typeof p.approvalId !== 'string' || !UUID_V4.test(p.approvalId) || typeof p.tenantId !== 'string' || !TENANT.test(p.tenantId)) return false;
  if (typeof p.actionHash !== 'string' || !HEX64.test(p.actionHash)) return false;
  if (typeof p.agentId !== 'string' || !UUID_V4.test(p.agentId) || typeof p.sessionId !== 'string' || !UUID_V4.test(p.sessionId)) return false;
  if (!isInt(p.seq, 1, SAFE)) return false;
  if (!idStr(p.requesterId) || !idStr(p.approverId) || !idStr(p.policyRuleId)) return false;
  if (p.decision !== 'APPROVED' && p.decision !== 'DENIED') return false;
  if (!isInt(p.notBefore, 1, SAFE) || !isInt(p.expiresAt, 1, SAFE) || p.expiresAt <= p.notBefore) return false;
  return p.mfa === 'step-up';
}

function digestOf(e) {
  const { canonical } = parseJcsP1(Buffer.from(JSON.stringify({ expiry: e.expiry, payload: e.payload, publicKeyId: e.publicKeyId, timestamp: e.timestamp }), 'utf8'));
  return crypto.createHash('sha256').update(DOMAIN, 'utf8').update(canonical, 'utf8').digest();
}

function verdict(input, keys) {
  const { envelope: e, now, expect = {} } = input;
  const no = (reason, detail) => ({ ok: false, reason, ...(detail ? { detail } : {}) });
  if (!isObj(e) || Object.keys(e).sort().join(',') !== ENVELOPE_KEYS) return no('APPROVAL_INVALID', 'shape');
  const p = e.payload;
  if (!shapeOk(p)) return no('APPROVAL_INVALID', 'shape');
  if (typeof e.signature !== 'string' || !SIG_RE.test(e.signature) || Buffer.from(e.signature, 'base64').toString('base64') !== e.signature) return no('APPROVAL_INVALID', 'shape');
  if (!isInt(e.timestamp, 1, SAFE) || e.expiry !== p.expiresAt || e.expiry <= e.timestamp || typeof e.publicKeyId !== 'string' || !e.publicKeyId.trim()) return no('APPROVAL_INVALID', 'shape');
  let digest;
  try { digest = digestOf(e); } catch { return no('APPROVAL_INVALID', 'shape'); }
  const key = keys.find((k) => k.publicKeyId === e.publicKeyId);
  if (!key) return no('APPROVAL_INVALID', 'signature');
  let ok = false;
  try { ok = crypto.verify(null, digest, crypto.createPublicKey({ key: Buffer.from(key.publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), Buffer.from(e.signature, 'base64')); } catch { ok = false; }
  if (!ok) return no('APPROVAL_INVALID', 'signature');
  if (p.tenantId !== key.clientId) return no('APPROVAL_INVALID', 'tenant');
  for (const k of ['actionHash', 'tenantId', 'agentId', 'sessionId', 'seq', 'approvalId']) if (expect[k] !== undefined && expect[k] !== p[k]) return no('APPROVAL_INVALID', `not for this ${k}`);
  if (p.approverId === p.requesterId) return no('APPROVAL_INVALID', 'the approver is the requester');
  if (p.decision !== 'APPROVED') return no('APPROVAL_INVALID', 'denied');
  if (e.timestamp > now + MAX_SKEW) return no('APPROVAL_INVALID', 'decided in the future');
  if (now < p.notBefore) return no('APPROVAL_INVALID', 'not yet valid');
  if (now >= p.expiresAt) return no('APPROVAL_EXPIRED');
  return { ok: true, digest: digest.toString('hex') };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function verifyFile(file) {
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  const failures = [];
  for (const c of v.cases) { const got = verdict(c.input, v.keys); if (!same(got, c.expected)) failures.push({ id: c.id, description: c.description, got, expected: c.expected }); }
  return { file: path.basename(file), family: v.family, cases: v.cases.length, failed: failures.length, failures };
}

module.exports = { verdict, verifyFile };

if (require.main === module) {
  const file = process.argv[2] || path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'approval.json');
  const r = verifyFile(file);
  process.stdout.write(`${JSON.stringify({ implementation: 'verify-approval-vectors.js (independent, node)', checks: r.cases, failed: r.failed, reports: [r] }, null, 2)}\n`);
  process.exit(r.failed ? 1 : 0);
}
