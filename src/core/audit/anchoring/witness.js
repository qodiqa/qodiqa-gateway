'use strict';

/**
 * — checkpoint WITNESSES.
 *
 * Signed checkpoints (../checkpoint/checkpoint.js) prove nothing against an insider: the checkpoint key lives on the
 * same host as the audit log, so anyone with host/DB access can truncate the chain, rewrite it, and re-sign fresh
 * checkpoints that verify. A witness closes that gap: an independent party (separate key, separate trust domain)
 * co-signs each checkpoint statement and keeps its OWN append-only log. Once a checkpoint at chain position N with
 * head H is witnessed, no later rewrite of entries ≤ N, rollback below N, or re-signed replacement of that checkpoint
 * can be presented as authentic — the witness's cosignature (and the customer-held anchor export, ./anchors.js)
 * still pins (N, H, payloadHash).
 *
 * Statement co-signed (domain-separated, canonical — restated in scripts/audit-repro/verify/anchors.js):
 *   SHA-256( "QODIQA::WITNESS_COSIGN::V1" || stableStringify({ v:1, witnessId, checkpointId, checkpointPayloadHash,
 *            chainLength, headHash, previousCheckpointHash, checkpointCreatedAt }) )
 *
 * A witness REFUSES (and records nothing) when asked to co-sign
 *   - a chainLength LOWER than the highest it has co-signed            → WITNESS_ROLLBACK_REFUSED
 *   - the SAME chainLength with a different headHash/payloadHash        → WITNESS_EQUIVOCATION_REFUSED
 *   - a HIGHER chainLength whose previousCheckpointHash is not the payload hash of the checkpoint it witnessed last
 *                                                                       → WITNESS_FORK_REFUSED
 * (/ M8, 2026-10-09: before this a forward fork — a fabricated head and predecessor above the witness's
 *     top — was co-signed. The only exception is an explicit, logged re-baseline bound to the exact statement:
 *     LocalFileWitness option `rebaselineAck` = "<chainLength>:<first 16 hex of checkpointPayloadHash>"; the log record
 *     then carries `rebaseline: { previousTop, ack }`.)
 * so a rolled-back history, or a fork at or above the witnessed position, cannot obtain a cosignature.
 *
 * INDEPENDENCE: a `local` witness runs inside the gateway process with a plaintext key file the
 * gateway reads — it is NOT independent of the gateway operator (anchoringIndependence() = 'none-local-witness').
 *
 * Witness kinds (QODIQA_WITNESS_MODE):
 *   none   (default) no witness
 *   local  LocalFileWitness: Ed25519 key at QODIQA_WITNESS_KEY_PATH (must NOT sit inside the gateway's key stores —
 *          intended for a volume/secret owned by another party), log at QODIQA_WITNESS_LOG_PATH. Useful for a
 *          customer-operated sidecar; it is only as independent as the custody of its key file.
 *   exec   ExecWitness: an operator-provided executable (QODIQA_WITNESS_EXEC) receives the statement JSON on stdin and
 *          prints {witnessId, keyId, signature, cosignedAt}. This is the adapter for a witness in another trust domain
 *          (a customer HSM, a separate service, a transparency witness) — QODIQA itself never contacts a network.
 * Verification of cosignatures always uses witness PUBLIC keys supplied out of band (QODIQA_WITNESS_PUBLIC_KEYS file).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const stableStringify = require('../../../utils/stableStringify');

const COSIGN_DOMAIN = 'QODIQA::WITNESS_COSIGN::V1';
const STATEMENT_FIELDS = Object.freeze(['v', 'witnessId', 'checkpointId', 'checkpointPayloadHash', 'chainLength', 'headHash',
  'previousCheckpointHash', 'checkpointCreatedAt']);

/** The statement a witness co-signs for a signed checkpoint. */
function statementFor(signedCheckpoint, witnessId) {
  const p = signedCheckpoint.payload;
  return {
    v: 1, witnessId, checkpointId: p.checkpointId, checkpointPayloadHash: signedCheckpoint.payloadHash,
    chainLength: p.chainLength, headHash: p.headHash, previousCheckpointHash: p.previousCheckpointHash ?? null,
    checkpointCreatedAt: p.createdAt,
  };
}

function statementDigest(statement) {
  const c = {}; for (const f of STATEMENT_FIELDS) c[f] = statement[f] === undefined ? null : statement[f];
  return crypto.createHash('sha256').update(COSIGN_DOMAIN, 'utf8').update(stableStringify(c), 'utf8').digest();
}

const TORN_MARK = '\t#torn'; // closes a crash-torn witness-log tail (LocalFileWitness._log)

function spkiKeyId(pubDerB64) {
  return 'wit-' + crypto.createHash('sha256').update(Buffer.from(pubDerB64, 'base64')).digest('hex').slice(0, 16);
}

/** Verify one cosignature against a trusted witness key set ({keys:[{witnessId?, keyId, publicKey, status}]}). */
function verifyCosignature(statement, cosig, trustedWitnessKeys) {
  const list = Array.isArray(trustedWitnessKeys) ? trustedWitnessKeys : ((trustedWitnessKeys && trustedWitnessKeys.keys) || []);
  const k = list.find((x) => x.keyId === cosig.keyId);
  if (!k) return { ok: false, reason: `WITNESS_KEY_UNTRUSTED:${cosig.keyId}` };
  if (['revoked', 'compromised'].includes(String(k.status || '').toLowerCase())) return { ok: false, reason: `WITNESS_KEY_REVOKED:${cosig.keyId}` };
  if (k.witnessId && cosig.witnessId !== k.witnessId) return { ok: false, reason: 'WITNESS_ID_MISMATCH' };
  if (statement.witnessId !== cosig.witnessId) return { ok: false, reason: 'WITNESS_STATEMENT_ID_MISMATCH' };
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(k.publicKey, 'base64'), format: 'der', type: 'spki' });
    const sig = Buffer.from(String(cosig.signature), 'base64');
    if (sig.length !== 64) return { ok: false, reason: 'WITNESS_SIGNATURE_MALFORMED' };
    return crypto.verify(null, statementDigest(statement), pub, sig) ? { ok: true } : { ok: false, reason: 'WITNESS_SIGNATURE_INVALID' };
  } catch (e) { return { ok: false, reason: `WITNESS_VERIFY_ERROR:${e.message}` }; }
}

class LocalFileWitness {
  /**
   * @param {{ witnessId: string, keyPath: string, logPath: string, now?: () => string }} o
   * The key file holds { keyId, privateKey (PKCS8 DER b64), publicKey (SPKI DER b64) }; created (0600) if absent.
   */
  constructor({ witnessId, keyPath, logPath, now = () => new Date().toISOString(), rebaselineAck = null }) {
    if (!witnessId || !keyPath || !logPath) throw new Error('LocalFileWitness: witnessId, keyPath and logPath are required');
    Object.assign(this, { witnessId, keyPath, logPath, now, rebaselineAck: rebaselineAck || null });
  }

  /** (M10): the highest statement this witness has co-signed, or null (never the private key). */
  head() {
    const top = this._log().reduce((m, r) => (!m || r.statement.chainLength > m.statement.chainLength ? r : m), null);
    return top ? { chainLength: top.statement.chainLength, checkpointPayloadHash: top.statement.checkpointPayloadHash, headHash: top.statement.headHash } : null;
  }

  _key() {
    if (!fs.existsSync(this.keyPath)) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
      const rec = { keyId: spkiKeyId(pub), witnessId: this.witnessId, publicKey: pub,
        privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') };
      fs.mkdirSync(path.dirname(this.keyPath), { recursive: true });
      fs.writeFileSync(this.keyPath, JSON.stringify(rec), { mode: 0o600, flag: 'wx' });
    }
    return JSON.parse(fs.readFileSync(this.keyPath, 'utf8'));
  }

  /** Public key record for the out-of-band trust set (never the private key). */
  publicKeyRecord() { const k = this._key(); return { witnessId: this.witnessId, keyId: k.keyId, publicKey: k.publicKey, status: 'active' }; }

  // phase 7 (crash recovery): a record is acknowledged only after its full line INCLUDING the '\n' is written and
  // fsynced, so a final segment without '\n' is a torn append from a crash (the gateway's timeout SIGKILLs a witness) and
  // was never returned to anyone: it is ignored. Previously it made every later call throw SyntaxError — a witness
  // wedged for good by one crash. A corrupt line that IS newline-terminated still throws (fail-closed).
  // The next append first CLOSES such a tail with TORN_MARK + '\n' (never truncates — the bytes stay as evidence), and a
  // line ending in TORN_MARK is skipped (JSON.stringify output never contains a raw tab, so no real record ends so).
  _log() {
    if (!fs.existsSync(this.logPath)) return [];
    const parts = fs.readFileSync(this.logPath, 'utf8').split('\n');
    parts.pop(); // '' after a final '\n', or the torn unterminated tail
    return parts.filter((l) => l && !l.endsWith(TORN_MARK)).map((l) => JSON.parse(l));
  }

  // phase 7 (concurrency): the read-check-append in cosign() is not atomic, and a reference witness runs one
  // PROCESS per request — 8 concurrent requests for the same chainLength with 8 different heads all obtained a
  // cosignature (10/10 probe rounds), i.e. the equivocation refusal could be bypassed by anyone able to send concurrent
  // requests (the gateway insider the witness exists to constrain). Each position is now CLAIMED before signing by an
  // atomic exclusive create (write a private temp file, hard-link it to <log>.positions/<chainLength>; link fails EEXIST
  // if any statement already claimed it). A claim holding a different statement digest is an equivocation. A crash after
  // the claim leaves the claim: the identical statement still signs (Ed25519 is deterministic), a different one is refused.
  _claimPosition(st) {
    const dir = `${this.logPath}.positions`;
    fs.mkdirSync(dir, { recursive: true });
    const claim = path.join(dir, String(st.chainLength));
    const digest = statementDigest(st).toString('hex');
    const tmp = path.join(dir, `.tmp-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
    fs.writeFileSync(tmp, digest, { mode: 0o600, flag: 'wx' });
    try { fs.linkSync(tmp, claim); } catch (e) { if (e.code !== 'EEXIST') throw e; } finally { fs.unlinkSync(tmp); }
    if (fs.readFileSync(claim, 'utf8') !== digest) {
      const e = new Error(`WITNESS_EQUIVOCATION_REFUSED: chainLength ${st.chainLength} was claimed by a different head/checkpoint`); e.code = 'WITNESS_EQUIVOCATION_REFUSED'; throw e;
    }
  }

  /** Co-sign a signed checkpoint, or refuse a rollback/equivocation. Appends to the witness's own log (fsynced). */
  cosign(signedCheckpoint) {
    const st = statementFor(signedCheckpoint, this.witnessId);
    const log = this._log();
    const top = log.reduce((m, r) => (!m || r.statement.chainLength > m.statement.chainLength ? r : m), null);
    if (top && st.chainLength < top.statement.chainLength) {
      const e = new Error(`WITNESS_ROLLBACK_REFUSED: chainLength ${st.chainLength} < witnessed ${top.statement.chainLength}`); e.code = 'WITNESS_ROLLBACK_REFUSED'; throw e;
    }
    const same = log.find((r) => r.statement.chainLength === st.chainLength);
    if (same) {
      if (same.statement.headHash !== st.headHash || same.statement.checkpointPayloadHash !== st.checkpointPayloadHash) {
        const e = new Error(`WITNESS_EQUIVOCATION_REFUSED: chainLength ${st.chainLength} was witnessed with a different head/checkpoint`); e.code = 'WITNESS_EQUIVOCATION_REFUSED'; throw e;
      }
      return same.cosignature; // idempotent
    }
    // M8: above the top, the new checkpoint must chain to the checkpoint witnessed last — otherwise it is a
    // forward fork (a rewritten history re-signed at a higher position). Refused unless an explicit re-baseline bound to
    // this exact statement is configured, and then recorded in the witness's own log.
    let rebaseline = null;
    if (top && st.previousCheckpointHash !== top.statement.checkpointPayloadHash) {
      const ack = `${st.chainLength}:${String(st.checkpointPayloadHash).slice(0, 16)}`;
      if (this.rebaselineAck !== ack) {
        const e = new Error(`WITNESS_FORK_REFUSED: chainLength ${st.chainLength} names predecessor ${st.previousCheckpointHash || 'null'}, but the checkpoint witnessed last (chainLength ${top.statement.chainLength}) is ${top.statement.checkpointPayloadHash} — a forked history. A deliberate re-baseline needs rebaselineAck=${ack}`);
        e.code = 'WITNESS_FORK_REFUSED'; throw e;
      }
      rebaseline = { previousTop: { chainLength: top.statement.chainLength, checkpointPayloadHash: top.statement.checkpointPayloadHash }, ack };
    }
    const k = this._key();
    fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
    this._claimPosition(st); // atomic per-position claim (see above) — BEFORE anything is signed
    const priv = crypto.createPrivateKey({ key: Buffer.from(k.privateKey, 'base64'), format: 'der', type: 'pkcs8' });
    const cosignature = { witnessId: this.witnessId, keyId: k.keyId, cosignedAt: this.now(),
      signature: crypto.sign(null, statementDigest(st), priv).toString('base64') };
    const fd = fs.openSync(this.logPath, 'a', 0o600);
    try {
      // a torn tail from a crash (ignored by _log) must not swallow this record's first bytes: start on a fresh line
      const size = fs.fstatSync(fd).size;
      let lead = '';
      if (size > 0) { const b = Buffer.alloc(1); const rfd = fs.openSync(this.logPath, 'r'); try { fs.readSync(rfd, b, 0, 1, size - 1); } finally { fs.closeSync(rfd); } if (b[0] !== 0x0a) lead = `${TORN_MARK}\n`; }
      fs.writeSync(fd, lead + JSON.stringify(rebaseline ? { statement: st, cosignature, rebaseline } : { statement: st, cosignature }) + '\n'); fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    return cosignature;
  }
}

// phase 7 (event loop, local mode): LocalFileWitness.cosign() is synchronous and re-reads + parses its WHOLE log
// on every call, so in QODIQA_WITNESS_MODE=local it blocked the gateway's event loop for a time that grows with the log
// (measured: 87 ms at 35,000 records ≈ one year at the 15-min default, 241 ms at 105,000). The gateway now runs it on a
// worker thread with a bounded wait; the synchronous class is unchanged (the reference exec witness uses it directly).
const _WORKER_SRC = `const { parentPort, workerData } = require('worker_threads');
try { const { LocalFileWitness } = require(workerData.mod); parentPort.postMessage({ ok: new LocalFileWitness(workerData.o).cosign(workerData.cp) }); }
catch (e) { parentPort.postMessage({ err: { message: String(e && e.message), code: e && e.code } }); }`;
class ThreadedLocalWitness {
  constructor({ witnessId, keyPath, logPath, timeoutMs = 10_000, rebaselineAck = null }) {
    this.inner = new LocalFileWitness({ witnessId, keyPath, logPath, rebaselineAck });
    Object.assign(this, { witnessId, keyPath, logPath, timeoutMs, rebaselineAck: rebaselineAck || null });
  }
  publicKeyRecord() { return this.inner.publicKeyRecord(); }
  head() { return this.inner.head(); } // (M10): boot cross-check of the export against the witness log
  cosign(signedCheckpoint) {
    const { Worker } = require('worker_threads');
    return new Promise((resolve, reject) => {
      let done = false;
      const settle = (fn, v) => { if (done) return; done = true; clearTimeout(timer); fn(v); };
      const fail = (message, code) => { const e = new Error(message); if (code) e.code = code; return e; };
      const w = new Worker(_WORKER_SRC, { eval: true, workerData: { mod: __filename, cp: JSON.parse(JSON.stringify(signedCheckpoint)),
        o: { witnessId: this.witnessId, keyPath: this.keyPath, logPath: this.logPath, rebaselineAck: this.rebaselineAck } } });
      const timer = setTimeout(() => { w.terminate().catch(() => {}); settle(reject, fail(`LocalFileWitness ${this.witnessId} timed out after ${this.timeoutMs} ms`, 'WITNESS_TIMEOUT')); }, this.timeoutMs);
      w.on('message', (m) => (m && m.ok ? settle(resolve, m.ok) : settle(reject, fail((m && m.err && m.err.message) || 'LocalFileWitness failed', m && m.err && m.err.code))));
      w.on('error', (e) => settle(reject, e));
      w.on('exit', (c) => settle(reject, fail(`LocalFileWitness ${this.witnessId} worker exited (${c}) without a result`, 'WITNESS_FAILED')));
    });
  }
}

// ER 2026-10-06: the witness command is another trust domain's adapter — it must not see the gateway's
// secrets (database passwords, KEK, provider keys). It receives only OS essentials, WITNESS_* / QODIQA_WITNESS_*
// variables, and any names the operator lists explicitly in QODIQA_WITNESS_EXEC_ENV_PASS (comma-separated).
const EXEC_ENV_BASE = ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR',
  'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TZ'];
function execWitnessEnv(env = process.env) {
  const pass = new Set([...EXEC_ENV_BASE, ...String(env.QODIQA_WITNESS_EXEC_ENV_PASS || '').split(',').map((s) => s.trim()).filter(Boolean)]);
  const out = {};
  for (const [k, v] of Object.entries(env)) if (pass.has(k) || /^(QODIQA_)?WITNESS_/.test(k)) out[k] = v;
  return out;
}

// ER 2026-10-06: the reference witness (scripts/anchor/witness-cosign.js) refuses with exit 3 and the refusal
// code on stderr. Surface it as e.code so checkpointWriter reports AUDIT_ANCHOR_WITNESS_REFUSED, not a generic failure.
// (M8): WITNESS_FORK_REFUSED joins them (a witness implementing the predecessor rule exits 3 with it).
const REFUSAL_CODES = ['WITNESS_ROLLBACK_REFUSED', 'WITNESS_EQUIVOCATION_REFUSED', 'WITNESS_FORK_REFUSED'];
function isWitnessRefusal(code) { return REFUSAL_CODES.includes(code); }

// phase 7: in-flight witness children are TRACKED so that
//   (a) a timeout settles the call at timeoutMs even when a grandchild (e.g. an ssh started by a wrapper script that
//       does not `exec`) still holds the stdout pipe — the old code waited for 'close', i.e. for the grandchild's
//       lifetime (Linux: 8,043 ms for a 500 ms timeout), and the single-flight checkpoint chain waited with it;
//   (b) the whole witness process tree is killed (POSIX: own process group, kill(-pid)), not only the direct child;
//   (c) nothing is orphaned when the gateway exits: a process 'exit' hook kills every in-flight witness (Linux: the
//       witness used to outlive the gateway; Windows' libuv job object already killed it), and the shutdown sequence
//       can call abortInFlightWitnesses() to stop them earlier and refuse new ones.
const _inFlight = new Set();
let _shuttingDown = false;
const _POSIX_GROUP = process.platform !== 'win32';
function _killTree(child) {
  try { if (_POSIX_GROUP && child.pid) { process.kill(-child.pid, 'SIGKILL'); return; } } catch { /* group already gone: fall through */ }
  try { child.kill('SIGKILL'); } catch { /* already exited */ }
}
function _killAllOnExit() { for (const c of _inFlight) _killTree(c); }
function _track(child) { if (_inFlight.size === 0) process.on('exit', _killAllOnExit); _inFlight.add(child); }
function _untrack(child) { if (_inFlight.delete(child) && _inFlight.size === 0) process.removeListener('exit', _killAllOnExit); }
/** Shutdown hook: kill every in-flight exec witness and refuse new cosign calls (WITNESS_SHUTTING_DOWN). Returns the count killed. */
function abortInFlightWitnesses() { _shuttingDown = true; const n = _inFlight.size; _killAllOnExit(); return n; }
function inFlightWitnessCount() { return _inFlight.size; }

/** Run command with `input` on stdin; resolves { status, signal, stdout, stderr, timedOut } (never rejects on exit status). */
function _runWithInput(command, args, input, { timeoutMs, env, maxBytes }) {
  return new Promise((resolve, reject) => {
    let child;
    try { child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, detached: _POSIX_GROUP }); } catch (e) { reject(e); return; }
    let stdout = ''; let stderr = ''; let done = false;
    const settle = (fn, v) => { if (done) return; done = true; clearTimeout(timer); _untrack(child); fn(v); };
    const abandon = () => { _killTree(child); for (const s of [child.stdin, child.stdout, child.stderr]) { try { s.destroy(); } catch { /* */ } } };
    _track(child);
    const timer = setTimeout(() => { abandon(); settle(resolve, { status: null, signal: 'SIGKILL', stdout, stderr, timedOut: true }); }, timeoutMs);
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; if (stdout.length > maxBytes && !done) { abandon(); settle(reject, new Error(`ExecWitness: witness output exceeded ${maxBytes} bytes`)); } });
    child.stderr.on('data', (d) => { stderr += d; if (stderr.length > maxBytes) stderr = stderr.slice(-maxBytes); });
    child.on('error', (e) => settle(reject, e)); // e.g. ENOENT: the witness command does not exist
    child.on('close', (status, signal) => settle(resolve, { status, signal, stdout, stderr, timedOut: false }));
    child.stdin.on('error', () => { /* the child may exit before reading stdin; reported via close */ });
    child.stdin.end(input);
  });
}

// phase 7: strict shape of a witness reply (fail-closed). An Ed25519 signature is exactly 64 bytes.
function _parseCosignature(stdout, witnessId) {
  const bad = (why) => { const e = new Error(`ExecWitness: malformed cosignature from witness command ${witnessId} (${why})`); e.code = 'WITNESS_MALFORMED_RESPONSE'; return e; };
  let c; try { c = JSON.parse(stdout); } catch { throw bad('stdout is not JSON'); }
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw bad('not an object');
  if (c.witnessId !== witnessId) throw bad('witnessId does not match');
  if (typeof c.keyId !== 'string' || !c.keyId || c.keyId.length > 128) throw bad('keyId');
  if (typeof c.signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(c.signature) || Buffer.from(c.signature, 'base64').length !== 64) throw bad('signature is not a base64 Ed25519 signature');
  if (c.cosignedAt !== undefined && (typeof c.cosignedAt !== 'string' || c.cosignedAt.length > 64)) throw bad('cosignedAt');
  return { witnessId: c.witnessId, keyId: c.keyId, cosignedAt: c.cosignedAt || new Date().toISOString(), signature: c.signature };
}

const MAX_EXEC_RETRIES = 3;
class ExecWitness {
  /** @param {{ witnessId: string, command: string, args?: string[], timeoutMs?: number, env?: object, retries?: number, retryDelayMs?: number }} o */
  constructor({ witnessId, command, args = [], timeoutMs = 10_000, env, retries = 1, retryDelayMs = 250 }) {
    if (!witnessId || !command) throw new Error('ExecWitness: witnessId and command are required');
    const r = Number.isInteger(retries) ? Math.min(Math.max(retries, 0), MAX_EXEC_RETRIES) : 1;
    Object.assign(this, { witnessId, command, args, timeoutMs, baseEnv: env, retries: r, retryDelayMs });
  }
  // ER 2026-10-06: asynchronous. The previous execFileSync blocked the whole event loop for the witness's
  // duration (up to timeoutMs per checkpoint; 1,554 ms measured for a 1.5 s witness). Same contract: statement JSON on
  // stdin, cosignature JSON on stdout, allow-listed env (M7), exit 3 + refusal code on stderr → e.code (M5).
  // phase 7: bounded retry (default 1, max 3) of TRANSIENT failures only — timeout, crash (signal) or a
  // non-zero exit other than 3 (refusal) and 64 (bad request). A witness is idempotent for the identical statement, so
  // a retry after a late/lost reply returns the same cosignature. Never retried: refusals, a missing command, a bad
  // request, a malformed reply, or anything after abortInFlightWitnesses().
  async cosign(signedCheckpoint) {
    for (let attempt = 0; ; attempt++) {
      try { return await this._cosignOnce(signedCheckpoint); } catch (e) {
        if (!e.transient || attempt >= this.retries || _shuttingDown) throw e;
        await new Promise((r) => setTimeout(r, this.retryDelayMs * (attempt + 1)));
      }
    }
  }

  async _cosignOnce(signedCheckpoint) {
    if (_shuttingDown) { const e = new Error(`ExecWitness: shutting down, ${this.witnessId} not contacted`); e.code = 'WITNESS_SHUTTING_DOWN'; throw e; }
    const st = statementFor(signedCheckpoint, this.witnessId);
    const r = await _runWithInput(this.command, this.args, JSON.stringify({ statement: st }),
      { timeoutMs: this.timeoutMs, env: execWitnessEnv(this.baseEnv || process.env), maxBytes: 1 << 20 });
    if (r.timedOut) { const e = new Error(`ExecWitness: witness command for ${this.witnessId} timed out after ${this.timeoutMs} ms`); e.code = 'WITNESS_TIMEOUT'; e.transient = true; throw e; }
    if (r.status !== 0) {
      const code = r.status === 3 ? REFUSAL_CODES.find((c) => r.stderr.includes(c)) : undefined;
      if (code) { const e = new Error(`${code}: refused by exec witness ${this.witnessId} (${r.stderr.trim().split('\n')[0].slice(0, 200)})`); e.code = code; throw e; }
      const e = new Error(`ExecWitness: witness command for ${this.witnessId} failed (exit ${r.status}${r.signal ? `, ${r.signal}` : ''}): ${r.stderr.trim().slice(0, 200)}`);
      e.status = r.status; e.stderr = r.stderr; e.code = r.status === 64 ? 'WITNESS_BAD_REQUEST' : 'WITNESS_FAILED'; e.transient = r.status !== 64 && r.status !== 3; throw e;
    }
    return _parseCosignature(r.stdout, this.witnessId);
  }
}

/**
 * several witnesses. QODIQA_WITNESSES_CONFIG is the path of a JSON array; each entry is
 * { witnessId, mode: 'exec'|'local', command, args[], retries, keyPath, logPath } (distinct witnessIds required). Every witness keeps
 * its own key and its own append-only log — in production each one is a separate process, ideally in a separate trust domain.
 */
function _witnessesFromConfigFile(file) {
  let list;
  try { list = JSON.parse(require('fs').readFileSync(file, 'utf8')); } catch (e) { throw new Error(`QODIQA_WITNESSES_CONFIG unreadable (${file}): ${e.message}`); }
  if (!Array.isArray(list) || list.length === 0) throw new Error('QODIQA_WITNESSES_CONFIG must be a non-empty JSON array');
  const seen = new Set();
  return list.map((c, i) => {
    if (!c || typeof c !== 'object' || typeof c.witnessId !== 'string' || !c.witnessId) throw new Error(`QODIQA_WITNESSES_CONFIG[${i}]: witnessId is required`);
    if (seen.has(c.witnessId)) throw new Error(`QODIQA_WITNESSES_CONFIG: duplicate witnessId ${c.witnessId}`);
    seen.add(c.witnessId);
    if (c.mode === 'exec') {
      if (typeof c.command !== 'string' || !c.command) throw new Error(`QODIQA_WITNESSES_CONFIG[${i}]: command is required for mode exec`);
      const retries = c.retries === undefined ? 1 : c.retries;
      if (!Number.isInteger(retries) || retries < 0 || retries > MAX_EXEC_RETRIES) throw new Error(`QODIQA_WITNESSES_CONFIG[${i}]: retries must be an integer 0..${MAX_EXEC_RETRIES}`);
      return new ExecWitness({ witnessId: c.witnessId, command: c.command, args: Array.isArray(c.args) ? c.args.map(String) : [], retries });
    }
    if (c.mode === 'local') {
      if (!c.keyPath || !c.logPath) throw new Error(`QODIQA_WITNESSES_CONFIG[${i}]: keyPath and logPath are required for mode local`);
      return new ThreadedLocalWitness({ witnessId: c.witnessId, keyPath: c.keyPath, logPath: c.logPath, rebaselineAck: c.rebaselineAck || null });
    }
    throw new Error(`QODIQA_WITNESSES_CONFIG[${i}]: mode must be exec|local`);
  });
}

/**
 * Cosignatures every anchor needs before it is exported: QODIQA_ANCHOR_MIN_WITNESSES when set, else 2 when two or more
 * witnesses are configured (the protocol asks for two independent signatures), else 1.
 */
function minWitnessesFromEnv(env = process.env, configured = null) {
  const n = Number(env.QODIQA_ANCHOR_MIN_WITNESSES);
  if (Number.isInteger(n) && n > 0) return n;
  const count = configured === null ? witnessesFromEnv(env).length : configured;
  return count >= 2 ? 2 : 1;
}

/** Witnesses configured by the environment ([] when QODIQA_WITNESS_MODE is none/unset). */
function witnessesFromEnv(env = process.env) {
  if (env.QODIQA_WITNESSES_CONFIG) return _witnessesFromConfigFile(env.QODIQA_WITNESSES_CONFIG);
  const mode = env.QODIQA_WITNESS_MODE || 'none';
  const witnessId = env.QODIQA_WITNESS_ID || 'witness-1';
  if (mode === 'none') return [];
  if (mode === 'local') return [new ThreadedLocalWitness({ witnessId, keyPath: env.QODIQA_WITNESS_KEY_PATH, logPath: env.QODIQA_WITNESS_LOG_PATH,
    rebaselineAck: env.QODIQA_WITNESS_REBASELINE_ACK || null })];
  if (mode === 'exec') {
    const retries = env.QODIQA_WITNESS_EXEC_RETRIES === undefined || env.QODIQA_WITNESS_EXEC_RETRIES === '' ? 1 : Number(env.QODIQA_WITNESS_EXEC_RETRIES);
    if (!Number.isInteger(retries) || retries < 0 || retries > MAX_EXEC_RETRIES) throw new Error(`QODIQA_WITNESS_EXEC_RETRIES must be an integer 0..${MAX_EXEC_RETRIES}, got ${env.QODIQA_WITNESS_EXEC_RETRIES}`);
    return [new ExecWitness({ witnessId, command: env.QODIQA_WITNESS_EXEC, args: (env.QODIQA_WITNESS_EXEC_ARGS || '').split(' ').filter(Boolean), retries })];
  }
  throw new Error(`QODIQA_WITNESS_MODE must be none|local|exec, got ${mode}`);
}

/**
 *what the configured witness mode says about operator independence — stated, never inferred.
 *   'none-no-witness'          no witness: anchors (if exported) are only as trustworthy as the export file's custody
 *   'none-local-witness'       QODIQA_WITNESS_MODE=local: the witness key is a plaintext file read by the gateway process
 *                              and its log sits on the gateway's storage — anyone controlling the gateway host controls
 *                              the witness. Detection logic runs; independence from the operator does NOT exist.
 *   'unverified-exec-witness'  QODIQA_WITNESS_MODE=exec: QODIQA cannot verify that the command reaches another trust
 *                              domain; that is the external acceptance contract (docs/security/audit-anchoring.md).
 */
function anchoringIndependence(env = process.env) {
  if (env.QODIQA_WITNESSES_CONFIG) return 'unverified-exec-witness';
  const mode = env.QODIQA_WITNESS_MODE || 'none';
  if (mode === 'local') return 'none-local-witness';
  if (mode === 'exec') return 'unverified-exec-witness';
  return 'none-no-witness';
}

module.exports = { COSIGN_DOMAIN, STATEMENT_FIELDS, statementFor, statementDigest, verifyCosignature, spkiKeyId,
  LocalFileWitness, ThreadedLocalWitness, ExecWitness, witnessesFromEnv, minWitnessesFromEnv, execWitnessEnv, abortInFlightWitnesses, inFlightWitnessCount, MAX_EXEC_RETRIES,
  REFUSAL_CODES, isWitnessRefusal, anchoringIndependence };
