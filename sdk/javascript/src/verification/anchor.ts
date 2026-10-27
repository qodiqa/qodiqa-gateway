/**
 * Offline check of one line of an anchors repository.
 *
 * A line is `{ digest, statement }`; `statement` is `{ v: 1, checkpointId, payloadHash, chainLength, headHash, createdAt }` and `digest` is
 * `hex(SHA-256("QODIQA::EXTERNAL_ANCHOR::V1" || canonical(statement)))`. The statement pins one signed audit checkpoint (its payload hash, chain
 * position and head) outside the gateway's trust domain; the digest is what an OpenTimestamps stamp or an RFC 3161 token is taken over.
 *
 * Fully offline, no network. This checks the LINE; whether the checkpoint is the one a proof relies on is the proof verifier's job
 * (`scripts/audit-repro/verify/qodiqa-proof-verify.js --anchors-repo`).
 *
 * @module
 */

import { stableStringify } from './canonicalJson.js';
import { domainSeparatedHash } from './domainHash.js';

export const ANCHOR_DOMAIN = 'QODIQA::EXTERNAL_ANCHOR::V1';
const STATEMENT_KEYS = ['chainLength', 'checkpointId', 'createdAt', 'headHash', 'payloadHash', 'v'];
const HEX64 = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export interface AnchorStatement {
  v: 1;
  checkpointId: string;
  payloadHash: string;
  chainLength: number;
  headHash: string;
  createdAt: string;
}

export type AnchorLineResult =
  | { ok: true; digest: string; statement: AnchorStatement }
  | { ok: false; code: 'ANCHOR_LINE_MALFORMED' | 'ANCHOR_DIGEST_MISMATCH' };

/** The digest (lowercase hex) of an anchor statement. */
export function anchorStatementDigest(statement: AnchorStatement): string {
  return domainSeparatedHash(ANCHOR_DOMAIN, stableStringify(statement)).toString('hex');
}

/** Check one raw line: the statement has exactly the documented shape and the digest is the statement's. */
export function checkAnchorLine(line: string): AnchorLineResult {
  if (line.endsWith('\r')) return { ok: false, code: 'ANCHOR_LINE_MALFORMED' };
  let rec: unknown;
  try { rec = JSON.parse(line); } catch { return { ok: false, code: 'ANCHOR_LINE_MALFORMED' }; }
  const st = rec !== null && typeof rec === 'object' && !Array.isArray(rec) ? (rec as { statement?: unknown }).statement : null;
  if (st === null || typeof st !== 'object' || Array.isArray(st) || Object.keys(st).sort().join(',') !== STATEMENT_KEYS.join(',')) return { ok: false, code: 'ANCHOR_LINE_MALFORMED' };
  const s = st as Record<string, unknown>;
  if (s.v !== 1 || typeof s.checkpointId !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(s.checkpointId) || !HEX64.test(String(s.payloadHash)) || !HEX64.test(String(s.headHash))
    || !Number.isSafeInteger(s.chainLength) || (s.chainLength as number) < 1 || typeof s.createdAt !== 'string' || !ISO_UTC.test(s.createdAt)) return { ok: false, code: 'ANCHOR_LINE_MALFORMED' };
  const digest = anchorStatementDigest(s as unknown as AnchorStatement);
  if ((rec as { digest?: unknown }).digest !== digest) return { ok: false, code: 'ANCHOR_DIGEST_MISMATCH' };
  return { ok: true, digest, statement: s as unknown as AnchorStatement };
}
