'use strict';

/**
 * External anchoring of signed audit checkpoints.
 *
 * A signed checkpoint (and its witness cosignatures, ./anchors.js) proves nothing against someone who controls the gateway host AND its keys. An
 * EXTERNAL anchor pins the checkpoint's position and head in a system that host does not control, with a time. Three kinds:
 *
 *   git      a commit in an anchors repository (QODIQA_ANCHOR_GIT_REPO, a working tree outside the gateway's control): the statement is appended to
 *            anchors/<UTC date>.jsonl and committed (signed with QODIQA_ANCHOR_GIT_SIGN=true, using the committer's configured git signing key).
 *            QODIQA never pushes: publishing the repository is the operator's job (a mirror / CI / a separate machine).
 *   ots      an OpenTimestamps stamp, produced by an operator-provided executable (QODIQA_ANCHOR_OTS_EXEC) — QODIQA itself contacts no network.
 *   rfc3161  an RFC 3161 timestamp token, produced the same way (QODIQA_ANCHOR_TSA_EXEC).
 *
 * The anchored STATEMENT is canonical and domain-separated, so an independent verifier recomputes it from the checkpoint alone:
 *     statement = { v: 1, checkpointId, payloadHash, chainLength, headHash, createdAt }
 *     digest    = SHA-256( "QODIQA::EXTERNAL_ANCHOR::V1" || canonicalJSON(statement) )        (hex; what is committed / stamped / timestamped)
 *
 * Asynchronous and never blocking: enqueue() records one row per configured kind in external_anchors (migration 099) and returns; a background
 * loop publishes, retries with a capped backoff, and reports. A failure is a counted, logged WARN (and a Prometheus alert on a stale pending
 * row) — never a refused request, never a refused checkpoint. At most one checkpoint per QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS (default 24 h) is
 * anchored unless force is passed (shutdown / operator).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const stableStringify = require('../../../utils/stableStringify');
const pgPool = require('../../../infra/postgres/pool');
const { emit } = require('../../../../services/logger');

const DOMAIN = 'QODIQA::EXTERNAL_ANCHOR::V1';
const KINDS = Object.freeze(['git', 'ots', 'rfc3161']);
const DEFAULT_INTERVAL_MS = 24 * 3600 * 1000;
const EXEC_TIMEOUT_MS = 30_000;
const MAX_ATTEMPTS = 10;
const LOOP_MS = 60_000;

/** The statement and its digest for a signed checkpoint { payload, payloadHash, signature }. */
function statementFor(signed) {
  const p = signed.payload;
  return { v: 1, checkpointId: p.checkpointId, payloadHash: signed.payloadHash, chainLength: p.chainLength, headHash: p.headHash, createdAt: p.createdAt };
}
function digestOf(statement) {
  return crypto.createHash('sha256').update(DOMAIN, 'utf8').update(stableStringify(statement), 'utf8').digest('hex');
}

function configuredKinds(env = process.env) {
  const k = [];
  if (env.QODIQA_ANCHOR_GIT_REPO) k.push('git');
  if (env.QODIQA_ANCHOR_OTS_EXEC) k.push('ots');
  if (env.QODIQA_ANCHOR_TSA_EXEC) k.push('rfc3161');
  return k;
}
function intervalMs(env = process.env) {
  const v = Number(env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS);
  return Number.isInteger(v) && v >= 1000 && v <= 7 * 24 * 3600 * 1000 ? v : DEFAULT_INTERVAL_MS;
}

function _metrics() { try { return require('../../../observability/metrics'); } catch { return null; } }
function _count(kind, outcome) { const m = _metrics(); try { if (m && m.externalAnchorTotal) m.externalAnchorTotal.inc({ kind, outcome }); } catch { /* metrics are fail-safe */ } }

// ── store: PostgreSQL (external_anchors) or, without PostgreSQL, process memory ──────────────────────────────────────────
const _mem = [];
let _memId = 0;
const usePg = () => pgPool.isEnabled();

async function _insertPending(row) {
  if (!usePg()) {
    if (_mem.some((r) => r.payload_hash === row.payload_hash && r.kind === row.kind)) return null;
    const r = { id: ++_memId, ...row, status: 'pending', receipt: null, receipt_ref: null, attempts: 0, last_error: null, created_at: new Date(), confirmed_at: null };
    _mem.push(r); return r;
  }
  const res = await pgPool.query(
    `INSERT INTO external_anchors (checkpoint_id, payload_hash, chain_length, head_hash, checkpoint_created_at, kind) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (payload_hash, kind) DO NOTHING RETURNING *`,
    [row.checkpoint_id, row.payload_hash, row.chain_length, row.head_hash, row.checkpoint_created_at, row.kind], 'external_anchor_insert');
  return res.rows[0] || null;
}
async function _pending() {
  if (!usePg()) return _mem.filter((r) => r.status === 'pending');
  return (await pgPool.query(`SELECT * FROM external_anchors WHERE status = 'pending' ORDER BY id ASC LIMIT 50`, [], 'external_anchor_pending')).rows;
}
async function _update(id, patch) {
  if (!usePg()) { const r = _mem.find((x) => x.id === id); if (r) Object.assign(r, patch, { updated_at: new Date() }); return; }
  await pgPool.query(
    `UPDATE external_anchors SET status = $2, receipt = $3, receipt_ref = $4, attempts = $5, last_error = $6, updated_at = now(),
            confirmed_at = CASE WHEN $2 = 'confirmed' THEN now() ELSE confirmed_at END WHERE id = $1`,
    [id, patch.status, patch.receipt ?? null, patch.receipt_ref ?? null, patch.attempts, patch.last_error ?? null], 'external_anchor_update');
}
async function listByPayloadHash(payloadHash) {
  if (!usePg()) return _mem.filter((r) => String(r.payload_hash).trim() === payloadHash);
  return (await pgPool.query('SELECT * FROM external_anchors WHERE payload_hash = $1 ORDER BY id', [payloadHash], 'external_anchor_by_hash')).rows;
}
async function list({ limit = 100 } = {}) {
  if (!usePg()) return _mem.slice(-limit);
  return (await pgPool.query(`SELECT * FROM external_anchors ORDER BY id DESC LIMIT $1`, [limit], 'external_anchor_list')).rows;
}

// ── publishers ──────────────────────────────────────────────────────────────────────────────────────────────────────────
function _run(cmd, args, { cwd, input, timeoutMs = EXEC_TIMEOUT_MS, env } = {}) {
  return new Promise((resolve, reject) => {
    // Windows cannot spawn a .cmd / .bat without a shell (Node >= 18.20 refuses with EINVAL); everything else runs without one
    const viaShell = process.platform === 'win32' && /.(cmd|bat)$/i.test(cmd);
    const child = spawn(viaShell ? `"${cmd}"` : cmd, args, { cwd, env: env || process.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: viaShell });
    let out = ''; let err = ''; let done = false;
    const t = setTimeout(() => { if (!done) { done = true; try { child.kill(); } catch { /* gone */ } reject(new Error(`${path.basename(cmd)} timed out after ${timeoutMs} ms`)); } }, timeoutMs);
    if (t.unref) t.unref();
    child.stdout.on('data', (d) => { out += d; if (out.length > 1_000_000) child.kill(); });
    child.stderr.on('data', (d) => { err += d; if (err.length > 100_000) err = err.slice(-100_000); });
    child.on('error', (e) => { if (!done) { done = true; clearTimeout(t); reject(e); } });
    child.on('close', (code) => { if (done) return; done = true; clearTimeout(t); code === 0 ? resolve({ out, err }) : reject(new Error(`${path.basename(cmd)} exited ${code}: ${err.trim().slice(0, 300)}`)); });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}

/**
 * the public keys a verifier needs to check a signed checkpoint / transparency root WITHOUT asking the gateway are committed beside the
 * anchors (keys/checkpoint-keys.json, keys/transparency-keys.json: { v:1, keys:[{ keyId, algorithm, publicKey (SPKI base64), status, … }] }).
 * Append-only by construction: a key is never dropped, only its status changes (and the change is a new commit). Public data only.
 * @returns {string[]} the repo-relative paths written (only when the content changed)
 */
function _planKeySets(repo, keySource) {
  const out = [];
  const sources = keySource || (() => {
    const src = {};
    try { src['checkpoint-keys.json'] = require('../checkpoint/checkpointKeyStore').listKeys(); } catch { /* store not initialised: skipped */ }
    try { src['transparency-keys.json'] = require('../../transparency/transparencyKeyStore').listKeys(); } catch { /* skipped */ }
    return src;
  })();
  for (const [name, list] of Object.entries(typeof sources === 'function' ? sources() : sources)) {
    if (!Array.isArray(list) || list.length === 0) continue;
    const rel = path.posix.join('keys', name); const file = path.join(repo, 'keys', name);
    let cur = { v: 1, keys: [] };
    try { cur = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* new file */ }
    const byId = new Map((cur.keys || []).map((k) => [k.keyId, k]));
    for (const k of list) {
      const pub = k.publicKeyB64 || k.publicKey;
      if (!k.keyId || !pub) continue;
      const rec = { keyId: k.keyId, algorithm: 'ed25519', publicKey: pub, status: k.status,
        ...(k.createdAt ? { activatedAt: k.createdAt } : {}), ...(k.retiredAt ? { retiredAt: k.retiredAt } : {}), ...(k.revokedAt ? { revokedAt: k.revokedAt } : {}) };
      const prev = byId.get(k.keyId);
      if (prev && prev.publicKey !== rec.publicKey) throw new Error(`key ${k.keyId} changed its public key in the anchors repository: refusing to overwrite`);   // a key id never changes its key
      if (prev && String(prev.status).toLowerCase() === 'revoked' && String(rec.status).toLowerCase() !== 'revoked') throw new Error(`key ${k.keyId} is revoked in the anchors repository and cannot become ${rec.status}`);   // D-2: revoked is absorbing
      byId.set(k.keyId, prev ? { ...prev, ...rec } : rec);
    }
    const next = `${JSON.stringify({ v: 1, keys: [...byId.values()].sort((a, b) => (a.keyId < b.keyId ? -1 : 1)) }, null, 2)}
`;
    if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== next) out.push({ rel, file, next });
  }
  return out;
}

// A3-05: git and the OTS/TSA adapters are third-party programs; they do not receive the gateway's whole environment (database passwords, KEK,
// provider keys). Like the witness adapter they get a small base set, the QODIQA_ANCHOR_* settings, and whatever the operator names in QODIQA_ANCHOR_EXEC_ENV_PASS.
const EXEC_ENV_BASE = ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TZ'];
function childEnv(env = process.env, extra = {}) {
  const pass = new Set([...EXEC_ENV_BASE, ...String(env.QODIQA_ANCHOR_EXEC_ENV_PASS || '').split(',').map((x) => x.trim()).filter(Boolean)]);
  const out = {};
  for (const [k, v] of Object.entries(env)) if (pass.has(k) || /^QODIQA_ANCHOR_/.test(k)) out[k] = v;
  return { ...out, ...extra };
}

async function publishGit(row, statement, digest, env = process.env, { keySource } = {}) {
  const repo = path.resolve(env.QODIQA_ANCHOR_GIT_REPO);
  if (!fs.existsSync(path.join(repo, '.git'))) throw new Error(`QODIQA_ANCHOR_GIT_REPO ${repo} is not a git working tree`);
  const day = new Date(statement.createdAt || Date.now()).toISOString().slice(0, 10);
  const rel = path.posix.join('anchors', `${day}.jsonl`);
  const file = path.join(repo, 'anchors', `${day}.jsonl`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const keyPlan = _planKeySets(repo, keySource);   // validated BEFORE the statement is appended: a refused key leaves the repository untouched
  const line = `${JSON.stringify({ digest, statement })}\n`;
  // D-5: a process killed mid-append leaves a torn, never-committed tail. When the committed (HEAD) content is a strict prefix of the file, the extra
  // bytes were never part of any commit: they are dropped (only those), so one crash cannot wedge publishing for good.
  if (fs.existsSync(file)) {
    const cur = fs.readFileSync(file, 'utf8');
    if (cur.length && !cur.endsWith('\n')) {
      let head = '';
      try { head = (await _run('git', ['-C', repo, 'show', `HEAD:${rel}`], { env: childEnv(env) })).out; } catch { head = ''; }
      if (cur.startsWith(head) && head.length < cur.length) fs.writeFileSync(file, head); else fs.appendFileSync(file, '\n');
    }
  }
  const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const has = existing.split('\n').some((l) => { if (!l) return false; try { return JSON.parse(l).digest === digest; } catch { return false; } });
  if (!has) fs.appendFileSync(file, line);   // idempotent re-publish
  const identity = env.QODIQA_ANCHOR_GIT_AUTHOR || 'QODIQA Anchor <anchor@qodiqa.invalid>';
  const m = /^(.*?)\s*<([^>]+)>$/.exec(identity) || [null, 'QODIQA Anchor', 'anchor@qodiqa.invalid'];
  const gitEnv = childEnv(env, { GIT_AUTHOR_NAME: m[1], GIT_AUTHOR_EMAIL: m[2], GIT_COMMITTER_NAME: m[1], GIT_COMMITTER_EMAIL: m[2] });
  for (const k of keyPlan) { fs.mkdirSync(path.dirname(k.file), { recursive: true }); fs.writeFileSync(k.file, k.next); }
  const rels = [rel, ...keyPlan.map((k) => k.rel)];
  // D-17: a publisher killed inside git leaves .git/index.lock, which blocks every later publish. A lock older than two minutes is a crash leftover
  // (git holds it for milliseconds): it is set aside (renamed, never deleted) so publishing resumes.
  try {
    const lock = path.join(repo, '.git', 'index.lock');
    if (fs.existsSync(lock) && Date.now() - fs.statSync(lock).mtimeMs > 120_000) { fs.renameSync(lock, `${lock}.stale-${Date.now()}`); emit('WARN', 'EXTERNAL_ANCHOR_STALE_GIT_LOCK_SET_ASIDE', { repo }); }
  } catch { /* best-effort: the git command below reports the lock */ }
  await _run('git', ['-C', repo, 'add', '--', ...rels], { env: gitEnv });
  const status = (await _run('git', ['-C', repo, 'status', '--porcelain', '--', ...rels], { env: gitEnv })).out.trim();
  if (status) {
    const sign = env.QODIQA_ANCHOR_GIT_SIGN === 'true' ? ['-S'] : ['--no-gpg-sign'];
    await _run('git', ['-C', repo, 'commit', '-q', ...sign, '-m', `anchor ${statement.chainLength} ${digest.slice(0, 16)}`, '--', ...rels], { env: gitEnv });
  }
  // D-12: the receipt is the commit that ADDED this digest (later anchors of the same day touch the same file)
  let sha = (await _run('git', ['-C', repo, 'log', '--reverse', '--format=%H', `-S${digest}`, '--', rel], { env: gitEnv })).out.trim().split('\n')[0];
  if (!sha) sha = (await _run('git', ['-C', repo, 'log', '-1', '--format=%H', '--', rel], { env: gitEnv })).out.trim();
  if (!/^[0-9a-f]{40,64}$/.test(sha)) throw new Error('could not read the anchor commit');
  return { receipt: sha, receipt_ref: `${rel}@${sha}` };
}

async function publishExec(kind, statement, digest, env = process.env) {
  const exe = kind === 'ots' ? env.QODIQA_ANCHOR_OTS_EXEC : env.QODIQA_ANCHOR_TSA_EXEC;
  const { out } = await _run(exe, [], { input: JSON.stringify({ kind, digestHex: digest, statement }), env: childEnv(env) });
  let parsed;
  try { parsed = JSON.parse(out); } catch { throw new Error(`${kind} adapter did not print JSON`); }
  if (!parsed || typeof parsed.receipt !== 'string' || !parsed.receipt) throw new Error(`${kind} adapter printed no receipt`);
  return { receipt: parsed.receipt, receipt_ref: typeof parsed.ref === 'string' ? parsed.ref : null };
}

// ── orchestration ───────────────────────────────────────────────────────────────────────────────────────────────────────
let _lastEnqueuedAt = 0;
let _processing = false;
let _again = false;     // rows were queued while a pass was running: the running pass goes round again
let _timer = null;
const _bgs = new Set();

/**
 * Record the anchors owed for a signed checkpoint (one per configured kind) and start publishing in the background. Never throws, never blocks.
 * @param {{ payload, payloadHash, signature }} signed
 * @param {{ force?: boolean, env?: object }} [opts]
 * @returns {Promise<{ queued: string[], skipped?: string }>}
 */
async function enqueue(signed, { force = false, env = process.env } = {}) {
  try {
    const kinds = configuredKinds(env);
    if (kinds.length === 0) return { queued: [], skipped: 'NOT_CONFIGURED' };
    const now = Date.now();
    if (!force && _lastEnqueuedAt && now - _lastEnqueuedAt < intervalMs(env)) return { queued: [], skipped: 'INTERVAL' };
    const st = statementFor(signed);
    const queued = [];
    for (const kind of kinds) {
      const r = await _insertPending({ checkpoint_id: st.checkpointId, payload_hash: st.payloadHash, chain_length: st.chainLength, head_hash: st.headHash, checkpoint_created_at: st.createdAt, kind });
      if (r) queued.push(kind);
    }
    _lastEnqueuedAt = now;
    start();
    const bg = new Promise((resolve) => { setImmediate(() => { processPending({ env }).catch(() => {}).finally(resolve); }); });
    _bgs.add(bg); bg.finally(() => _bgs.delete(bg));
    return { queued };
  } catch (err) {
    emit('WARN', 'EXTERNAL_ANCHOR_ENQUEUE_FAILED', { error: err.message });
    return { queued: [], skipped: 'ERROR' };
  }
}

/** Publish every pending row once. Failures are recorded on the row (attempts, last_error) and counted; a row that fails MAX_ATTEMPTS times is `failed`. */
async function processPending({ env = process.env } = {}) {
  if (_processing) { _again = true; return { published: 0, failed: 0, skipped: true }; }
  _processing = true;
  let published = 0; let failed = 0;
  try {
   do {
    _again = false;
    for (const row of await _pending()) {
      // the statement is rebuilt from the stored columns, exactly as statementFor() derived it from the checkpoint
      const stmt = { v: 1, checkpointId: row.checkpoint_id, payloadHash: String(row.payload_hash).trim(), chainLength: Number(row.chain_length), headHash: String(row.head_hash).trim(), createdAt: row.checkpoint_created_at };
      const digest = digestOf(stmt);
      try {
        const out = row.kind === 'git' ? await publishGit(row, stmt, digest, env) : await publishExec(row.kind, stmt, digest, env);
        await _update(row.id, { status: 'confirmed', receipt: out.receipt, receipt_ref: out.receipt_ref, attempts: Number(row.attempts) + 1, last_error: null });
        _count(row.kind, 'confirmed'); published++;
      } catch (err) {
        const attempts = Number(row.attempts) + 1;
        const status = attempts >= MAX_ATTEMPTS ? 'failed' : 'pending';
        await _update(row.id, { status, receipt: null, receipt_ref: null, attempts, last_error: String(err.message).slice(0, 500) });
        _count(row.kind, status === 'failed' ? 'failed' : 'retry'); failed++;
        emit('WARN', 'EXTERNAL_ANCHOR_FAILED', { kind: row.kind, chainLength: Number(row.chain_length), attempts, status, error: err.message });
      }
    }
   } while (_again);
  } finally { _processing = false; }
  _gauge();
  return { published, failed };
}

async function _gauge() {
  try {
    const m = _metrics(); if (!m || !m.externalAnchorPending) return;
    const rows = await _pending();
    m.externalAnchorPending.set(rows.length);
    if (m.externalAnchorOldestPendingSeconds) m.externalAnchorOldestPendingSeconds.set(rows.length ? Math.max(0, Math.floor((Date.now() - new Date(rows[0].created_at).getTime()) / 1000)) : 0);
  } catch { /* gauges are best-effort */ }
}

/** Resolves when the background publication kicked off by the last enqueue() has finished (tests, shutdown). */
function settle() { return Promise.all([..._bgs]).then(() => undefined); }

function start() {
  if (_timer) return;
  _timer = setInterval(() => { processPending().catch(() => {}); }, LOOP_MS);
  if (_timer.unref) _timer.unref();
}
function stop() { if (_timer) { clearInterval(_timer); _timer = null; } }

function _reset() { _bgs.clear(); _mem.length = 0; _memId = 0; _lastEnqueuedAt = 0; _processing = false; _again = false; stop(); }

module.exports = { settle, statementFor, digestOf, configuredKinds, intervalMs, enqueue, processPending, list, listByPayloadHash, start, stop, publishGit, publishExec, childEnv, KINDS, DOMAIN, MAX_ATTEMPTS, _reset };
