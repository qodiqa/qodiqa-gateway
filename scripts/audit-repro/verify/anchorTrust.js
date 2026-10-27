'use strict';

/**
 * Independent verifier — "trust from the anchor" mode. NO src/ import, Node built-ins and the sibling verifier modules only.
 *
 * Normal mode takes the public keys and the checkpoint from the document under verification, i.e. from the party that produced it.
 * This mode takes them from the ANCHORS REPOSITORY instead — a git working tree that the gateway only appended to and that the operator
 * mirrors outside the gateway's control (docs/configuration/reference.md section 20). Layout, as written by the gateway:
 *
 *   anchors/<UTC date>.jsonl   one line per anchored checkpoint: { digest, statement }
 *                              statement = { v:1, checkpointId, payloadHash, chainLength, headHash, createdAt }
 *                              digest    = SHA-256( "QODIQA::EXTERNAL_ANCHOR::V1" || canonical(statement) ), hex
 *   keys/checkpoint-keys.json, keys/transparency-keys.json
 *                              { v:1, keys:[ { keyId, algorithm, publicKey (SPKI base64), status, … } ] }   public data, append-only
 *
 * Checks (findings use these codes; a finding makes the verdict INVALID):
 *   ANCHOR_REPO_UNREADABLE / ANCHOR_REPO_NOT_GIT   the directory is not a readable git working tree
 *   ANCHOR_REPO_DIRTY                              uncommitted changes under anchors/ or keys/ (edited after the fact)
 *   ANCHOR_HISTORY_REWRITTEN                       a committed version of an anchors file is not a prefix of the next one, or a key changed
 *   ANCHOR_COMMIT_UNSIGNED                         --require-signed and a commit touching anchors/ or keys/ does not verify
 *   ANCHOR_LINE_MALFORMED / ANCHOR_DIGEST_MISMATCH a line is not a statement of this format, or its digest is not the statement's
 *   ANCHORS_NOT_MONOTONIC                          an anchored position decreases or a later anchor has an earlier creation time
 *   ANCHOR_FORK                                    two anchors for the same position name different heads
 *   KEYS_MALFORMED                                 a key file is not of this format
 *
 * Proof evaluation (evaluateProof): the proof's signed checkpoint must verify under the ANCHORED checkpoint keys, its statement must be (or be
 * covered by) an anchored statement, and every request entry must lie at or before the anchored head on the contiguous chain path.
 * What this does NOT establish: the repository's own history is as trustworthy as its custody (a history rewritten and force-pushed
 * everywhere looks like a fresh history — compare with a mirror you did not take from the same source), and git commit times are the
 * committer's claim, so `anchoredAt` is informational. OpenTimestamps / RFC 3161 receipts are not evaluated here.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { canonicalize } = require('./canonical');
const checkpoint = require('./checkpoint');

const DOMAIN = 'QODIQA::EXTERNAL_ANCHOR::V1';
const HEX64 = /^[0-9a-f]{64}$/;
const STATEMENT_KEYS = ['chainLength', 'checkpointId', 'createdAt', 'headHash', 'payloadHash', 'v'];   // sorted
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;   // D-4: the one timestamp format the gateway writes
const ID_RE = /^[\x21-\x7e]{1,256}$/;   // D-18: printable ASCII only (no look-alike or line-separator characters)
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

const statementDigest = (st) => crypto.createHash('sha256').update(DOMAIN, 'utf8').update(canonicalize(st), 'utf8').digest('hex');

function git(dir, args) {
  return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
}
const tryGit = (dir, args) => { try { return { ok: true, out: git(dir, args) }; } catch (e) { return { ok: false, err: String(e.stderr || e.message).trim() }; } };

// D-6: the files are those of the COMMITTED tree (HEAD), never of the working tree (an untracked, ignored or assume-unchanged file is not evidence).
function listFiles(dir, sub, ext) {
  const r = tryGit(dir, ['ls-tree', '-r', '--name-only', 'HEAD', '--', sub]);
  return r.ok ? r.out.split('\n').filter((p) => p.startsWith(`${sub}/`) && p.endsWith(ext)).sort() : [];
}
const headFile = (dir, rel) => { const r = tryGit(dir, ['show', `HEAD:${rel}`]); return r.ok ? r.out : null; };

/**
 * One line of anchors/<date>.jsonl: { digest, statement } with a statement of exactly the documented shape and the digest of THAT statement.
 * @returns {{ ok: true, record: object } | { ok: false, code: 'ANCHOR_LINE_MALFORMED'|'ANCHOR_DIGEST_MISMATCH', detail: string }}
 */
function checkLine(line) {
  if (line.endsWith('\r')) return { ok: false, code: 'ANCHOR_LINE_MALFORMED', detail: 'ends with a carriage return' };   // D-4: both verifiers refuse CRLF
  let rec; try { rec = JSON.parse(line); } catch { return { ok: false, code: 'ANCHOR_LINE_MALFORMED', detail: 'is not JSON' }; }
  const st = isObj(rec) ? rec.statement : null;
  if (!isObj(st) || Object.keys(st).sort().join(',') !== STATEMENT_KEYS.join(',') || st.v !== 1 || typeof st.checkpointId !== 'string' || !ID_RE.test(st.checkpointId)
    || !HEX64.test(String(st.payloadHash)) || !HEX64.test(String(st.headHash)) || !Number.isSafeInteger(st.chainLength) || st.chainLength < 1 || typeof st.createdAt !== 'string' || !ISO_UTC.test(st.createdAt)) {
    return { ok: false, code: 'ANCHOR_LINE_MALFORMED', detail: 'is not a statement of this format' };
  }
  if (rec.digest !== statementDigest(st)) return { ok: false, code: 'ANCHOR_DIGEST_MISMATCH', detail: "digest is not the statement's" };
  return { ok: true, record: rec };
}

/**
 * Read and check the repository.
 * @returns {{ statements: object[], keys: { checkpoint: object[], transparency: object[] }, findings: {code, detail}[], head: string|null }}
 */
function loadAnchorRepo(dir, { requireSigned = false } = {}) {
  const findings = []; const f = (code, detail) => findings.push({ code, detail });
  const out = { statements: [], keys: { checkpoint: [], transparency: [] }, findings, head: null, commits: 0 };
  if (!dir || !fs.existsSync(dir)) { f('ANCHOR_REPO_UNREADABLE', `${dir} does not exist`); return out; }
  if (!tryGit(dir, ['rev-parse', '--git-dir']).ok) { f('ANCHOR_REPO_NOT_GIT', `${dir} is not a git working tree`); return out; }
  const headR = tryGit(dir, ['rev-parse', 'HEAD']);
  out.head = headR.ok ? headR.out.trim() : null;
  if (!out.head) { f('ANCHOR_REPO_UNREADABLE', 'the repository has no commits'); return out; }

  const dirty = tryGit(dir, ['status', '--porcelain', '--', 'anchors', 'keys']);
  if (dirty.ok && dirty.out.trim()) f('ANCHOR_REPO_DIRTY', dirty.out.trim().split('\n').slice(0, 5).join('; '));

  const anchorFiles = listFiles(dir, 'anchors', '.jsonl'); const keyFiles = listFiles(dir, 'keys', '.json');
  const touched = new Set();
  // D-15: a merge commit (e.g. `merge -s ours`) can hide a rewritten history from path-limited logs: the anchors repository must be linear
  { const mg = tryGit(dir, ['rev-list', '--merges', 'HEAD']); if (mg.ok && mg.out.trim()) f('ANCHOR_HISTORY_REWRITTEN', `the history contains merge commit(s) (${mg.out.trim().split('\n').length}): an anchors repository must be linear`); }
  // D-1: a file that ever existed under anchors/ or keys/ and is gone at HEAD is a deleted or renamed record
  { const ever = tryGit(dir, ['log', '--full-history', '--name-only', '--format=', '--', 'anchors', 'keys']);
    if (ever.ok) for (const p of new Set(ever.out.split('\n').filter(Boolean))) if (/^(anchors\/[^/]+\.jsonl|keys\/[^/]+\.json)$/.test(p) && !anchorFiles.includes(p) && !keyFiles.includes(p)) f('ANCHOR_HISTORY_REWRITTEN', `${p} existed in the history and is gone at HEAD (deleted or renamed)`); }
  // ── history: every committed version must extend the previous one (append-only) ──
  for (const rel of [...anchorFiles, ...keyFiles]) {
    const log = tryGit(dir, ['log', '--reverse', '--full-history', '--format=%H', '--', rel]);
    const commits = log.ok ? log.out.split('\n').filter(Boolean) : [];
    let prev = null;
    for (const c of commits) {
      touched.add(c);
      const show = tryGit(dir, ['show', `${c}:${rel}`]);
      if (!show.ok) continue;     // the file was removed in this commit: the working-tree check below catches a missing file
      if (prev !== null) {
        if (rel.endsWith('.jsonl')) {
          const a = prev.split('\n').filter(Boolean); const b = show.out.split('\n').filter(Boolean);
          if (a.length > b.length || a.some((l, i) => l !== b[i])) f('ANCHOR_HISTORY_REWRITTEN', `${rel} at ${c.slice(0, 12)} is not an extension of the previous version`);
        } else {
          try {
            const pa = new Map(JSON.parse(prev).keys.map((k) => [k.keyId, k])); const nb = new Map(JSON.parse(show.out).keys.map((k) => [k.keyId, k]));
            for (const [id, k] of pa) {
              const n = nb.get(id);
              if (!n || n.publicKey !== k.publicKey) f('ANCHOR_HISTORY_REWRITTEN', `${rel} at ${c.slice(0, 12)}: key ${id} was removed or changed`);
              else if (String(k.status).toLowerCase() === 'revoked' && String(n.status).toLowerCase() !== 'revoked') f('ANCHOR_HISTORY_REWRITTEN', `${rel} at ${c.slice(0, 12)}: key ${id} was revoked and is no longer`);   // D-2: revoked is absorbing
            }
          } catch { f('KEYS_MALFORMED', `${rel} at ${c.slice(0, 12)} is not valid JSON`); }
        }
      }
      prev = show.out;
    }
  }
  out.commits = touched.size;
  if (requireSigned) {
    for (const c of touched) if (!tryGit(dir, ['verify-commit', c]).ok) f('ANCHOR_COMMIT_UNSIGNED', `commit ${c.slice(0, 12)} has no valid signature`);
  }
  // ── statements ──
  for (const rel of anchorFiles) {
    const lines = (headFile(dir, rel) || '').split('\n');
    lines.forEach((line, i) => {
      if (!line.trim()) return;
      const c = checkLine(line);
      if (!c.ok) { f(c.code, `${rel}:${i + 1} ${c.detail}`); return; }
      const rec = c.record; const st = rec.statement;
      out.statements.push({ digest: rec.digest, statement: st, file: rel, line: i + 1 });
    });
  }
  // ── monotonic, fork-free ──
  const byPos = new Map(); let prev = null;
  for (const a of out.statements) {
    const s = a.statement;
    const seen = byPos.get(s.chainLength);
    if (seen && seen.headHash !== s.headHash) f('ANCHOR_FORK', `position ${s.chainLength} is anchored with two heads (${seen.checkpointId}, ${s.checkpointId})`);
    byPos.set(s.chainLength, s);
    if (prev && (s.chainLength < prev.chainLength || Date.parse(s.createdAt) < Date.parse(prev.createdAt))) f('ANCHORS_NOT_MONOTONIC', `${s.checkpointId} (${s.chainLength}) after ${prev.checkpointId} (${prev.chainLength})`);
    prev = s;
  }
  // ── keys ──
  for (const [name, slot] of [['checkpoint-keys.json', 'checkpoint'], ['transparency-keys.json', 'transparency']]) {
    const text = headFile(dir, `keys/${name}`);
    if (text === null) continue;
    try {
      const doc = JSON.parse(text);
      if (!isObj(doc) || doc.v !== 1 || !Array.isArray(doc.keys) || !doc.keys.every((k) => isObj(k) && typeof k.keyId === 'string' && typeof k.publicKey === 'string' && typeof k.status === 'string')) throw new Error('shape');
      out.keys[slot] = doc.keys;
    } catch { f('KEYS_MALFORMED', `keys/${name} is not of this format`); }
  }
  return out;
}

/**
 * Evaluate a proof against the loaded repository.
 * @returns {{ checks: {id, ok, detail?}[], failed: {id, code}[], partial: string[], covered: boolean }}
 */
function evaluateProof(doc, repo) {
  const checks = []; const failed = []; const partial = [];
  const pass = (id, detail) => checks.push({ id, ok: true, ...(detail ? { detail } : {}) });
  const fail = (id, code, detail) => { checks.push({ id, ok: false, detail: detail || code }); failed.push({ id, code }); };

  if (repo.findings.length) { for (const x of repo.findings) fail('ANCHOR_REPO', x.code, x.detail); return { checks, failed, partial, covered: false }; }
  if (!repo.statements.length) { partial.push('ANCHORS_EMPTY'); return { checks, failed, partial, covered: false }; }
  pass('ANCHOR_REPO', `${repo.statements.length} anchored checkpoint(s), ${repo.commits} commit(s)`);

  const cp = isObj(doc.checkpoint) ? doc.checkpoint : null;
  if (!cp) { partial.push('CHECKPOINT_ABSENT'); return { checks, failed, partial, covered: false }; }

  // the proof's own key list must agree with the anchored keys wherever both name a key
  const proofKeys = Array.isArray(doc.keys) ? doc.keys : [];
  const anchoredKeys = new Map([...repo.keys.checkpoint, ...repo.keys.transparency].map((k) => [k.keyId, k]));
  const differs = proofKeys.filter((k) => anchoredKeys.has(k.keyId) && anchoredKeys.get(k.keyId).publicKey !== k.publicKeySpkiB64).map((k) => k.keyId);
  if (differs.length) fail('ANCHOR_KEYS', 'PROOF_KEY_DIFFERS_FROM_ANCHORED', differs.join(','));
  else pass('ANCHOR_KEYS');

  // the signed checkpoint under the ANCHORED checkpoint keys
  const v = checkpoint.verifySignedCheckpoint(cp, checkpoint.keyResolver({ keys: repo.keys.checkpoint }));
  if (v.ok) pass('ANCHOR_CHECKPOINT_SIGNATURE'); else fail('ANCHOR_CHECKPOINT_SIGNATURE', v.reason || 'CHECKPOINT_INVALID', 'the checkpoint does not verify under the anchored checkpoint keys');
  if (!v.ok) return { checks, failed, partial, covered: false };

  const p = cp.payload;
  const direct = repo.statements.find((a) => a.statement.payloadHash === cp.payloadHash);
  const samePos = repo.statements.find((a) => a.statement.chainLength === p.chainLength);
  const path_ = Array.isArray(doc.chainPath) ? doc.chainPath : [];
  const idx = new Map(path_.map((e, i) => [e.hash, i]));
  let covered = false;
  if (direct) {
    const s = direct.statement;
    if (s.checkpointId !== p.checkpointId || s.chainLength !== p.chainLength || s.headHash !== p.headHash || s.createdAt !== p.createdAt) fail('CHECKPOINT_ANCHORED', 'ANCHOR_STATEMENT_MISMATCH', 'same payload hash, different statement fields');
    else { pass('CHECKPOINT_ANCHORED', `${direct.file}:${direct.line}`); covered = true; }
  } else if (samePos && samePos.statement.headHash !== p.headHash) {
    fail('CHECKPOINT_ANCHORED', 'CHECKPOINT_FORKS_ANCHOR', `position ${p.chainLength} is anchored with a different head`);
  } else {
    // not anchored itself: covered when an anchored head lies on the contiguous chain path at or after every request entry
    const entryIdx = (Array.isArray(doc.auditEntries) ? doc.auditEntries : []).map((e) => idx.get(e.hash));
    const lastEntry = entryIdx.length && entryIdx.every((i) => i !== undefined) ? Math.max(...entryIdx) : null;
    const cover = lastEntry === null ? null : repo.statements.find((a) => idx.has(a.statement.headHash) && idx.get(a.statement.headHash) >= lastEntry);
    if (cover) { pass('CHECKPOINT_ANCHORED', `the request's entries precede the anchored head of ${cover.statement.checkpointId}`); covered = true; }
    else partial.push('CHECKPOINT_NOT_COVERED_BY_ANCHOR');
  }
  return { checks, failed, partial, covered };
}

module.exports = { DOMAIN, statementDigest, checkLine, loadAnchorRepo, evaluateProof };
