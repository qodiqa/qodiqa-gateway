'use strict';

/**
 * ER — ExecWitness hardening from the local simulation:
 *   M7  the exec witness inherited the gateway's FULL environment (database passwords, KEK, provider keys). It now gets
 *       only OS essentials, WITNESS_* / QODIQA_WITNESS_* and names listed in QODIQA_WITNESS_EXEC_ENV_PASS.
 *   M5  the reference witness's refusal protocol (exit 3, code on stderr) surfaced as a generic error, so a rollback or
 *       equivocation attempt was reported as AUDIT_ANCHOR_WITNESS_FAILED instead of AUDIT_ANCHOR_WITNESS_REFUSED.
 * Real child processes: the reference witness scripts/anchor/witness-cosign.js and small probe scripts. No network.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { ExecWitness, LocalFileWitness, statementFor, verifyCosignature, execWitnessEnv } = require('../witness');

const REPO = path.join(__dirname, '..', '..', '..', '..', '..');
const COSIGN = path.join(REPO, 'scripts', 'anchor', 'witness-cosign.js');
let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-execwit-')); });

const cp = (chainLength, headHash, prev = null) => {
  const payload = { checkpointId: crypto.randomUUID(), chainLength, headHash, previousCheckpointHash: prev, createdAt: '2026-10-06T00:00:00.000Z' };
  return { payload, payloadHash: crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex') };
};
const H = (n) => crypto.createHash('sha256').update(`head-${n}`).digest('hex');

function referenceWitness(extraEnv = {}) {
  const keyPath = path.join(dir, 'witness-key.json'); const logPath = path.join(dir, 'witness-log.jsonl');
  const trust = new LocalFileWitness({ witnessId: 'w-ext', keyPath, logPath }).publicKeyRecord(); // creates the key
  const env = { ...process.env, WITNESS_ID: 'w-ext', WITNESS_KEY_PATH: keyPath, WITNESS_LOG_PATH: logPath, ...extraEnv };
  return { w: new ExecWitness({ witnessId: 'w-ext', command: process.execPath, args: [COSIGN], env }), trust };
}

describe('ExecWitness (ER / M5, M7)', () => {
  test('EW-01 a genuine cosignature from the reference witness verifies against its public trust record', async () => {
    const { w, trust } = referenceWitness();
    const signed = cp(10, H(10));
    const c = await w.cosign(signed);
    expect(verifyCosignature(statementFor(signed, 'w-ext'), c, { keys: [trust] })).toEqual({ ok: true });
  });

  test('EW-02 M5: a rollback refusal (exit 3) carries e.code WITNESS_ROLLBACK_REFUSED', async () => {
    const { w } = referenceWitness();
    await w.cosign(cp(44, H(44)));
    let err; try { await w.cosign(cp(10, H(10))); } catch (e) { err = e; }
    expect(err).toBeDefined();
    expect(err.code).toBe('WITNESS_ROLLBACK_REFUSED');
    expect(err.message).toMatch(/^WITNESS_ROLLBACK_REFUSED: refused by exec witness w-ext/);
  });

  test('EW-03 M5: an equivocation refusal (same position, different head) carries e.code WITNESS_EQUIVOCATION_REFUSED', async () => {
    const { w } = referenceWitness();
    await w.cosign(cp(44, H(44)));
    let err; try { await w.cosign(cp(44, 'f'.repeat(64))); } catch (e) { err = e; }
    expect(err.code).toBe('WITNESS_EQUIVOCATION_REFUSED');
  });

  test('EW-04 M5: other failures are NOT classified as refusals (exit 3 without a refusal code; exit 1 with one)', async () => {
    const s3 = path.join(dir, 'exit3.js'); fs.writeFileSync(s3, 'process.stderr.write("something else"); process.exit(3);');
    const s1 = path.join(dir, 'exit1.js'); fs.writeFileSync(s1, 'process.stderr.write("WITNESS_ROLLBACK_REFUSED but crashed"); process.exit(1);');
    for (const script of [s3, s1]) {
      let err; try { await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [script] }).cosign(cp(1, H(1))); } catch (e) { err = e; }
      expect(err).toBeDefined();
      expect(['WITNESS_ROLLBACK_REFUSED', 'WITNESS_EQUIVOCATION_REFUSED']).not.toContain(err.code);
    }
  });

  test('EW-05 M7: the witness process does not see gateway secrets; it sees OS essentials, WITNESS_* and explicit pass-through names', async () => {
    const probe = path.join(dir, 'probe.js');
    fs.writeFileSync(probe, `require('fs').writeFileSync(${JSON.stringify(path.join(dir, 'seen.json'))}, JSON.stringify(Object.keys(process.env)));
      process.stdout.write(JSON.stringify({ witnessId: 'w', keyId: 'k', signature: ${JSON.stringify(Buffer.alloc(64, 7).toString('base64'))}, cosignedAt: 't' }));`);
    const env = { ...process.env, QODIQA_PG_PASSWORD: 'secret-pg', QODIQA_KEY_ENCRYPTION_KEY: 'secret-kek', OPENAI_API_KEY: 'secret-ai',
      QODIQA_EXECUTION_INVARIANT_SECRET: 'secret-inv', WITNESS_ENDPOINT: 'w-endpoint', QODIQA_WITNESS_ID: 'w', AWS_PROFILE: 'witness-hsm',
      QODIQA_WITNESS_EXEC_ENV_PASS: 'AWS_PROFILE' };
    await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [probe], env }).cosign(cp(1, H(1)));
    const seen = JSON.parse(fs.readFileSync(path.join(dir, 'seen.json'), 'utf8'));
    for (const secret of ['QODIQA_PG_PASSWORD', 'QODIQA_KEY_ENCRYPTION_KEY', 'OPENAI_API_KEY', 'QODIQA_EXECUTION_INVARIANT_SECRET']) expect(seen).not.toContain(secret);
    expect(seen).toEqual(expect.arrayContaining(['WITNESS_ENDPOINT', 'QODIQA_WITNESS_ID', 'AWS_PROFILE']));
  });

  test('EW-06 execWitnessEnv: allow-list only; pass-through list is trimmed and comma-separated', () => {
    const out = execWitnessEnv({ PATH: '/bin', QODIQA_PG_PASSWORD: 'x', HF_TOKEN: 'y', WITNESS_A: '1', QODIQA_WITNESS_B: '2', EXTRA_ONE: '3', EXTRA_TWO: '4', NOT_LISTED: '5', QODIQA_WITNESS_EXEC_ENV_PASS: ' EXTRA_ONE , EXTRA_TWO' });
    expect(Object.keys(out).sort()).toEqual(['EXTRA_ONE', 'EXTRA_TWO', 'PATH', 'QODIQA_WITNESS_B', 'QODIQA_WITNESS_EXEC_ENV_PASS', 'WITNESS_A']);
  });

  test('EW-07 M6: co-signing is asynchronous — a 50 ms timer fires on time while a ~1.5 s witness runs', async () => {
    const { w } = referenceWitness();
    const slow = path.join(dir, 'slow.js');
    fs.writeFileSync(slow, `const t=Date.now();while(Date.now()-t<1500){};require(${JSON.stringify(COSIGN)});`);
    const sw = new ExecWitness({ witnessId: 'w-ext', command: process.execPath, args: [slow], env: w.baseEnv });
    // 2026-10-14 (final mission): "asynchronous" is asserted deterministically — right after cosign() returns its
    // promise the witness must still be IN FLIGHT (a synchronous implementation returns only after the child finished,
    // count 0) — and the timer bound is measured from that return, so Windows process-creation time inside the
    // synchronous spawn() (up to ~3 s under parallel gate load; S-05, EW-22) is not charged to the event loop.
    const { inFlightWitnessCount } = require('../witness');
    const armed = Date.now(); let firedAfter = null; const t = setTimeout(() => { firedAfter = Date.now() - armed; }, 50);
    const pending = sw.cosign(cp(5, H(5))); const syncMs = Date.now() - armed; const inFlightAtReturn = inFlightWitnessCount();
    const c = await pending;
    clearTimeout(t);
    expect(c.witnessId).toBe('w-ext');
    expect(inFlightAtReturn).toBe(1);
    expect(firedAfter).not.toBeNull();
    expect(firedAfter - syncMs).toBeLessThan(1000);
  });

  test('EW-08 a missing witness command rejects promptly with ENOENT (as the synchronous implementation did: sim step 8), it does not hang', async () => {
    const { publishAnchor } = require('../anchors');
    const miss = new ExecWitness({ witnessId: 'w', command: path.join(dir, 'no-such-witness.exe') });
    const r = await publishAnchor(cp(3, H(3)), { witnesses: [miss], exportPath: path.join(dir, 'anchors.jsonl') });
    expect(r.record.cosignatures).toHaveLength(0);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0].code).toBe('ENOENT');
  });

  // failure-mode matrix for the exec witness.
  const script = (name, body) => { const p = path.join(dir, name); fs.writeFileSync(p, body); return p; };
  // phase 7: replies are now shape-checked (a 64-byte base64 Ed25519 signature), so the stub signature is a
  // well-formed (but untrusted) 64-byte value instead of 'x'.
  const SIG64 = Buffer.alloc(64, 7).toString('base64');
  const VALID = (id) => `process.stdout.write(JSON.stringify({ witnessId: '${id}', keyId: 'k', signature: '${SIG64}', cosignedAt: 't' }));`;

  test('EW-09 timeout: a hung witness is killed after timeoutMs, the call rejects, and the event loop stays responsive', async () => {
    const hang = script('hang.js', 'setInterval(() => {}, 1000);');
    // 2026-10-14 (launch plan, flake root cause, round4): the old bound `tick < 500` also measured the OS's process-
    // creation time. On Windows under parallel gate load Node's own spawn() (CreateProcessW inside the synchronous
    // uv_spawn) measured p90 345 ms / max 381 ms with no QODIQA code involved (logs/ew09-raw-spawn-under-load.txt), so a
    // correct asynchronous witness failed at 551 ms. The property is now asserted directly: (1) cosign() returns its
    // promise long before the timeout — the earlier execFileSync held the call for the FULL timeout, so it still fails
    // here; (2) once the call has returned, the loop is free: the 50 ms timer fires within 500 ms of that point. The
    // timeout is 3 s (was 800 ms) so (1) keeps a wide margin over the observed spawn latency.
    const w = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [hang], timeoutMs: 3000, retries: 0 });
    // Final mission: round 5 showed Node's own synchronous process creation taking ~3 s under gate load
    // (EW-22), so no wall-clock bound may include it. The OS work is timed where it happens — ChildProcess#spawn, which
    // child_process.spawn() calls synchronously — and only QODIQA's OWN synchronous work is bounded:
    //   (1) at return the witness is still IN FLIGHT (the earlier execFileSync returned only after the whole timeout);
    //   (2) syncMs − spawnMs < 500: any blocking QODIQA adds around the spawn is caught; the OS's latency is not charged;
    //   (3) after the call returned, the 50 ms timer fires within 500 ms (the wait for the witness is asynchronous).
    // Mutation-checked: final-mission/test-review.md (historic execFileSync shape and a blocking delay on the spawn
    // path both FAIL this test).
    const { ChildProcess } = require('child_process');
    const { inFlightWitnessCount } = require('../witness');
    const realSpawn = ChildProcess.prototype.spawn; let spawnMs = 0;
    ChildProcess.prototype.spawn = function timedSpawn(...a) { const t0 = process.hrtime.bigint(); try { return realSpawn.apply(this, a); } finally { spawnMs += Number(process.hrtime.bigint() - t0) / 1e6; } };
    let syncMs; let inFlightAtReturn; let pending; let started; let tick = null; let t;
    try {
      const armed = Date.now(); t = setTimeout(() => { tick = Date.now() - armed; }, 50);
      started = Date.now(); pending = w.cosign(cp(1, H(1))); syncMs = Date.now() - started; inFlightAtReturn = inFlightWitnessCount();
    } finally { ChildProcess.prototype.spawn = realSpawn; }
    let err; try { await pending; } catch (e) { err = e; } clearTimeout(t);
    expect(err && err.message).toMatch(/timed out after 3000 ms/);
    expect(inFlightAtReturn).toBe(1); // (1)
    expect(syncMs - spawnMs).toBeLessThan(500); // (2)
    expect(Date.now() - started - syncMs).toBeLessThan(10000);
    expect(tick).not.toBeNull(); expect(tick - syncMs).toBeLessThan(500); // (3)
  });

  test('EW-10 late response: output written after the timeout is ignored (the call has already rejected)', async () => {
    const late = script('late.js', `setTimeout(() => { ${VALID('w')} }, 1500);`);
    const w = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [late], timeoutMs: 500 });
    await expect(w.cosign(cp(1, H(1)))).rejects.toThrow(/timed out/);
  });

  test('EW-11 malformed responses are rejected: non-JSON stdout, missing fields, or another witness id', async () => {
    for (const [name, body] of [['nonjson.js', 'process.stdout.write("not json");'], ['missing.js', "process.stdout.write(JSON.stringify({ witnessId: 'w' }));"], ['other.js', VALID('someone-else')]]) {
      const w = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [script(name, body)] });
      await expect(w.cosign(cp(1, H(1)))).rejects.toThrow();
    }
  });

  test('EW-12 crash: a witness that dies mid-request (non-zero exit, no output) is a failure, not a refusal', async () => {
    const crash = script('crash.js', 'process.stderr.write("boom"); process.abort();');
    let err; try { await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [crash] }).cosign(cp(1, H(1))); } catch (e) { err = e; }
    expect(err).toBeDefined();
    expect(['WITNESS_ROLLBACK_REFUSED', 'WITNESS_EQUIVOCATION_REFUSED']).not.toContain(err.code);
  });

  test('EW-13 replay: the same checkpoint co-signed twice returns the identical cosignature (idempotent, no new log entry)', async () => {
    const { w } = referenceWitness(); const signed = cp(7, H(7));
    const a = await w.cosign(signed); const b = await w.cosign(signed);
    expect(b).toEqual(a);
    expect(fs.readFileSync(path.join(dir, 'witness-log.jsonl'), 'utf8').trim().split(/\r?\n/)).toHaveLength(1);
  });

  test('EW-14 recovery and restart: after a failed call the next succeeds; a NEW witness process still refuses a rollback below its log', async () => {
    const bad = new ExecWitness({ witnessId: 'w-ext', command: path.join(dir, 'missing.exe') });
    await expect(bad.cosign(cp(1, H(1)))).rejects.toThrow();
    const first = referenceWitness(); const c30 = cp(30, H(30)); await first.w.cosign(c30);
    const restarted = new ExecWitness({ witnessId: 'w-ext', command: process.execPath, args: [COSIGN], env: first.w.baseEnv }); // same log + key, fresh process
    let err; try { await restarted.cosign(cp(29, H(29))); } catch (e) { err = e; }
    expect(err && err.code).toBe('WITNESS_ROLLBACK_REFUSED');
    await expect(restarted.cosign(cp(31, H(31), c30.payloadHash))).resolves.toEqual(expect.objectContaining({ witnessId: 'w-ext' }));
  });

  test('EW-15 publishAnchor with one healthy and one failing witness still exports the record with the healthy cosignature', async () => {
    const { publishAnchor } = require('../anchors');
    const { w } = referenceWitness(); const down = new ExecWitness({ witnessId: 'w-down', command: path.join(dir, 'gone.exe') });
    const r = await publishAnchor(cp(9, H(9)), { witnesses: [down, w], exportPath: path.join(dir, 'anchors.jsonl') });
    expect(r.record.cosignatures.map((c) => c.witnessId)).toEqual(['w-ext']);
    expect(r.errors.map((e) => e.witnessId)).toEqual(['w-down']);
  });

  // ── phase 7: ──────────────────────────────
  const pidAlive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
  const waitFor = async (pred, ms = 5000) => { const t = Date.now(); while (!pred()) { if (Date.now() - t > ms) return false; await new Promise((r) => setTimeout(r, 20)); } return true; };
  const counting = (name, bodyByAttempt) => script(name, `const fs=require('fs');const f=${JSON.stringify(path.join(dir, name + '.count'))};
    const n=(fs.existsSync(f)?+fs.readFileSync(f,'utf8'):0)+1;fs.writeFileSync(f,String(n));${bodyByAttempt}`);
  const attempts = (name) => +fs.readFileSync(path.join(dir, name + '.count'), 'utf8');

  test('EW-16 malformed reply shapes are refused fail-closed with code WITNESS_MALFORMED_RESPONSE (signature must be a 64-byte base64 Ed25519 value)', async () => {
    const replies = {
      'sig-x.js': { witnessId: 'w', keyId: 'k', signature: 'x' },
      'sig-63.js': { witnessId: 'w', keyId: 'k', signature: Buffer.alloc(63, 1).toString('base64') },
      'sig-notb64.js': { witnessId: 'w', keyId: 'k', signature: '!'.repeat(88) },
      'keyid-num.js': { witnessId: 'w', keyId: 5, signature: SIG64 },
      'cosignedat-obj.js': { witnessId: 'w', keyId: 'k', signature: SIG64, cosignedAt: { evil: true } },
    };
    for (const [name, reply] of Object.entries(replies)) {
      const w = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [script(name, `process.stdout.write(${JSON.stringify(JSON.stringify(reply))});`)] });
      await expect(w.cosign(cp(1, H(1)))).rejects.toMatchObject({ code: 'WITNESS_MALFORMED_RESPONSE' });
    }
    for (const body of ['process.stdout.write("not json");', 'process.stdout.write("[1,2]");', 'process.stdout.write("null");']) {
      const w = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [script('m.js', body)] });
      await expect(w.cosign(cp(1, H(1)))).rejects.toMatchObject({ code: 'WITNESS_MALFORMED_RESPONSE' });
    }
  });

  test('EW-17 audit binding at publish: a cosignature that does not verify for THIS checkpoint (replayed from another one) is reported WITNESS_COSIGNATURE_UNVERIFIED', async () => {
    const { publishAnchor } = require('../anchors');
    const { w, trust } = referenceWitness();
    const a = cp(12, H(12)); const b = cp(13, H(13), a.payloadHash);
    const ok = await publishAnchor(a, { witnesses: [w], exportPath: path.join(dir, 'x.jsonl'), trustedWitnessKeys: { keys: [trust] } });
    expect(ok.errors).toEqual([]);
    const cosigA = ok.record.cosignatures[0];
    const replaying = { witnessId: 'w-ext', cosign: async () => cosigA }; // a witness (or transport) replaying A's cosignature for B
    const r = await publishAnchor(b, { witnesses: [replaying], exportPath: path.join(dir, 'x.jsonl'), trustedWitnessKeys: { keys: [trust] } });
    expect(r.errors).toEqual([expect.objectContaining({ witnessId: 'w-ext', code: 'WITNESS_COSIGNATURE_UNVERIFIED' })]);
    expect(r.errors[0].message).toMatch(/WITNESS_SIGNATURE_INVALID/);
    expect(r.record.cosignatures).toEqual([cosigA]); // kept as evidence; the verifier ignores it
    // wrong trust record at the gateway: reported at publish, not first at the next boot
    const other = new LocalFileWitness({ witnessId: 'w-ext', keyPath: path.join(dir, 'o', 'k.json'), logPath: path.join(dir, 'o', 'l.jsonl') }).publicKeyRecord();
    const c20 = cp(20, H(20), a.payloadHash); // (M8): successors chain to the last witnessed checkpoint
    const wrong = await publishAnchor(c20, { witnesses: [w], exportPath: path.join(dir, 'x.jsonl'), trustedWitnessKeys: { keys: [other] } });
    expect(wrong.errors).toEqual([expect.objectContaining({ code: 'WITNESS_COSIGNATURE_UNVERIFIED', message: expect.stringMatching(/WITNESS_KEY_UNTRUSTED/) })]);
    // no trusted keys configured → no publish-time check (non-production; the boot check stays the authority)
    expect((await publishAnchor(cp(21, H(21), c20.payloadHash), { witnesses: [w], exportPath: path.join(dir, 'x.jsonl'), trustedWitnessKeys: [] })).errors).toEqual([]);
  });

  test('EW-18 checkpoint binding: changing ANY statement field (id, payload hash, position, head, predecessor, createdAt, witness) invalidates the cosignature', async () => {
    const { w, trust } = referenceWitness(); const signed = cp(15, H(15), 'a'.repeat(64));
    const st = statementFor(signed, 'w-ext'); const c = await w.cosign(signed);
    expect(verifyCosignature(st, c, { keys: [trust] })).toEqual({ ok: true });
    const mutations = { checkpointId: crypto.randomUUID(), checkpointPayloadHash: 'b'.repeat(64), chainLength: 16, headHash: H(99),
      previousCheckpointHash: null, checkpointCreatedAt: '2026-10-07T00:00:00.000Z', v: 2 };
    for (const [k, v] of Object.entries(mutations)) expect(verifyCosignature({ ...st, [k]: v }, c, { keys: [trust] })).toEqual({ ok: false, reason: 'WITNESS_SIGNATURE_INVALID' });
    expect(verifyCosignature({ ...st, witnessId: 'w-other' }, c, { keys: [trust] }).ok).toBe(false);
  });

  test('EW-19 trust boundary: witness and checkpoint keys are separate, domain-separated, and the witness key is never accepted as a checkpoint signer', () => {
    const { signCheckpoint, verifyCheckpoint } = require('../../checkpoint/checkpoint');
    const keyPath = path.join(dir, 'wk.json');
    const lw = new LocalFileWitness({ witnessId: 'w-tb', keyPath, logPath: path.join(dir, 'wl.jsonl') });
    const rec = lw.publicKeyRecord();
    expect(Object.keys(rec).sort()).toEqual(['keyId', 'publicKey', 'status', 'witnessId']); // never the private key
    expect(rec.keyId).toMatch(/^wit-[0-9a-f]{16}$/);
    const wk = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    const witnessAsCheckpointKey = { keyId: rec.keyId, version: 1, privDer: Buffer.from(wk.privateKey, 'base64'), pubDer: Buffer.from(wk.publicKey, 'base64') };
    const forged = signCheckpoint({ chainLength: 5, headHash: H(5) }, { keyStore: { ensureActiveKey: () => witnessAsCheckpointKey } });
    const realCheckpointKeys = new Map(); // the gateway's checkpoint trust store holds no wit- key
    expect(verifyCheckpoint(forged, { resolvePublicKey: (id) => { const k = realCheckpointKeys.get(id); if (!k) throw new Error(`unknown checkpoint key ${id}`); return k; } }).reason).toMatch(/^CHECKPOINT_KEY_UNAVAILABLE/);
    // domain separation: even if an operator put the witness key into the checkpoint trust store, a COSIGNATURE is not a checkpoint signature
    const genuine = signCheckpoint({ chainLength: 6, headHash: H(6) }, { keyStore: { ensureActiveKey: () => witnessAsCheckpointKey } });
    const resolveWitnessKey = () => witnessAsCheckpointKey.pubDer;
    expect(verifyCheckpoint(genuine, { resolvePublicKey: resolveWitnessKey })).toEqual({ ok: true }); // control
    const cosig = lw.cosign(genuine);
    expect(verifyCheckpoint({ ...genuine, signature: cosig.signature }, { resolvePublicKey: resolveWitnessKey })).toEqual({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' });
    // and the exec witness never sees the gateway's key-store locations or key material
    const seen = execWitnessEnv({ PATH: '/bin', QODIQA_KEYS_PATH: '/k', QODIQA_CHECKPOINT_KEYS_PATH: '/c', QODIQA_TRANSPARENCY_KEYS_PATH: '/t', QODIQA_MAC_KEYS_PATH: '/m', QODIQA_KEY_ENCRYPTION_KEY: 'kek' });
    expect(Object.keys(seen)).toEqual(['PATH']);
  });

  test('EW-20 no secret leakage: stdin carries only the statement, argv only the configured args, and error messages never carry gateway env values', async () => {
    const secrets = { QODIQA_PG_PASSWORD: 'SECRET-PG-0f1e', QODIQA_KEY_ENCRYPTION_KEY: 'SECRET-KEK-77aa', OPENAI_API_KEY: 'SECRET-AI-91bc', QODIQA_ADMIN_KEY: 'SECRET-ADM-3c3c' };
    const env = { ...process.env, ...secrets };
    const rec = path.join(dir, 'rec.json');
    const probe = script('rec.js', `const fs=require('fs');const input=fs.readFileSync(0,'utf8');
      fs.writeFileSync(${JSON.stringify(rec)}, JSON.stringify({ input, argv: process.argv.slice(2), env: process.env }));
      process.stderr.write('witness stderr: ' + JSON.stringify(process.env)); process.exit(1);`);
    let err; try { await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [probe, '--flag'], env, retries: 0 }).cosign(cp(2, H(2))); } catch (e) { err = e; }
    const seen = JSON.parse(fs.readFileSync(rec, 'utf8'));
    expect(Object.keys(JSON.parse(seen.input))).toEqual(['statement']);
    expect(Object.keys(JSON.parse(seen.input).statement).sort()).toEqual(['checkpointCreatedAt', 'checkpointId', 'checkpointPayloadHash', 'chainLength', 'headHash', 'previousCheckpointHash', 'v', 'witnessId'].sort());
    expect(seen.argv).toEqual(['--flag']);
    const blob = JSON.stringify(seen) + err.message + String(err.stderr);
    for (const v of Object.values(secrets)) expect(blob).not.toContain(v);
    // timeout and malformed-reply messages carry no env either
    const hang = script('hang2.js', 'setInterval(() => {}, 1000);');
    const t = await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [hang], env, timeoutMs: 300, retries: 0 }).cosign(cp(2, H(2))).catch((e) => e);
    const m = await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [script('echoenv.js', 'process.stdout.write(JSON.stringify(process.env));')], env, retries: 0 }).cosign(cp(2, H(2))).catch((e) => e);
    for (const e of [t, m]) for (const v of Object.values(secrets)) expect(e.message).not.toContain(v);
  });

  test('EW-21 retry is BOUNDED and only for transient failures: a crash/timeout is retried once by default; refusals, bad requests, malformed replies and a missing command are not', async () => {
    const flaky = counting('flaky.js', `if (n === 1) { process.stderr.write('transient'); process.exit(1); } ${VALID('w')}`);
    await expect(new ExecWitness({ witnessId: 'w', command: process.execPath, args: [flaky], retryDelayMs: 10 }).cosign(cp(1, H(1)))).resolves.toMatchObject({ witnessId: 'w' });
    expect(attempts('flaky.js')).toBe(2);
    const noRetry = counting('flaky0.js', `if (n === 1) process.exit(1); ${VALID('w')}`);
    await expect(new ExecWitness({ witnessId: 'w', command: process.execPath, args: [noRetry], retries: 0 }).cosign(cp(1, H(1)))).rejects.toMatchObject({ code: 'WITNESS_FAILED' });
    expect(attempts('flaky0.js')).toBe(1);
    const cases = [['refuse.js', 'process.stderr.write("WITNESS_ROLLBACK_REFUSED: x"); process.exit(3);', 'WITNESS_ROLLBACK_REFUSED'],
      ['bad.js', 'process.exit(64);', 'WITNESS_BAD_REQUEST'], ['malf.js', 'process.stdout.write("{}");', 'WITNESS_MALFORMED_RESPONSE']];
    for (const [name, body, code] of cases) {
      await expect(new ExecWitness({ witnessId: 'w', command: process.execPath, args: [counting(name, body)], retries: 3, retryDelayMs: 10 }).cosign(cp(1, H(1)))).rejects.toMatchObject({ code });
      expect(attempts(name)).toBe(1);
    }
    const always = counting('always.js', 'process.exit(1);');
    await expect(new ExecWitness({ witnessId: 'w', command: process.execPath, args: [always], retries: 99, retryDelayMs: 10 }).cosign(cp(1, H(1)))).rejects.toMatchObject({ code: 'WITNESS_FAILED' });
    expect(attempts('always.js')).toBe(4); // clamped to MAX_EXEC_RETRIES = 3
    const { witnessesFromEnv } = require('../witness');
    const envBase = { QODIQA_WITNESS_MODE: 'exec', QODIQA_WITNESS_EXEC: process.execPath };
    expect(witnessesFromEnv(envBase)[0].retries).toBe(1);
    expect(witnessesFromEnv({ ...envBase, QODIQA_WITNESS_EXEC_RETRIES: '0' })[0].retries).toBe(0);
    for (const bad of ['7', '-1', 'abc', '1.5']) expect(() => witnessesFromEnv({ ...envBase, QODIQA_WITNESS_EXEC_RETRIES: bad })).toThrow(/QODIQA_WITNESS_EXEC_RETRIES/);
  });

  test('EW-22 timeout is honoured even when a grandchild holds the stdout pipe (wrapper that does not exec), and the witness tree is killed', async () => {
    const gpid = path.join(dir, 'grandchild.pid');
    const wrapper = script('wrapper.js', `const { spawn } = require('child_process');
      const g = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 8000)'], { stdio: 'inherit' });
      require('fs').writeFileSync(${JSON.stringify(gpid)}, String(g.pid)); setInterval(() => {}, 1000);`);
    // Final mission: measured from when cosign() returns (the timeout timer is armed after the synchronous
    // spawn()). Round 5: 3,564 ms total on Windows, of which the spawn alone was ~2.8 s; on Linux the real code takes
    // 702–707 ms and a faithful pre-fix mutant 8,038–8,047 ms (logs/ew22-linux-real-vs-mutant.json), so the bound still
    // separates the fix from the bug. (On Windows the bug cannot occur: the OS tears down the whole tree.)
    const started = Date.now();
    const pending = new ExecWitness({ witnessId: 'w', command: process.execPath, args: [wrapper], timeoutMs: 700, retries: 0 }).cosign(cp(1, H(1)));
    const syncMs = Date.now() - started;
    const err = await pending.catch((e) => e);
    expect(err.code).toBe('WITNESS_TIMEOUT');
    expect(Date.now() - started - syncMs).toBeLessThan(3000); // pre-fix on Linux: ~8,000 ms (the grandchild's lifetime)
    if (process.platform !== 'win32') { // POSIX: the witness runs in its own process group and the whole group is killed
      const pid = +fs.readFileSync(gpid, 'utf8');
      expect(await waitFor(() => !pidAlive(pid), 2000)).toBe(true);
    }
  });

  test('EW-23 shutdown: abortInFlightWitnesses() kills an in-flight witness at once (no retry, no wait for the timeout) and refuses new calls', async () => {
    await new Promise((resolve, reject) => jest.isolateModules(() => { // fresh module: the shutdown flag is process-wide by design
      const fresh = require('../witness');
      const pidFile = path.join(dir, 'inflight.pid');
      const hang = script('hang3.js', `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000);`);
      const w = new fresh.ExecWitness({ witnessId: 'w', command: process.execPath, args: [hang], timeoutMs: 30_000, retries: 3 });
      const p = w.cosign(cp(1, H(1))).catch((e) => e);
      (async () => {
        expect(await waitFor(() => fs.existsSync(pidFile))).toBe(true);
        expect(fresh.inFlightWitnessCount()).toBe(1);
        // Final mission: "at once" is measured from the abort, not from before the spawn (whose Windows
        // process-creation time under load is not the property). Pre-fix the call waited for the 30 s timeout.
        const aborted = Date.now();
        expect(fresh.abortInFlightWitnesses()).toBe(1);
        const e = await p;
        expect(e).toBeInstanceOf(Error);
        expect(Date.now() - aborted).toBeLessThan(5000);
        expect(fresh.inFlightWitnessCount()).toBe(0);
        expect(await waitFor(() => !pidAlive(+fs.readFileSync(pidFile, 'utf8')), 2000)).toBe(true);
        await expect(w.cosign(cp(2, H(2)))).rejects.toMatchObject({ code: 'WITNESS_SHUTTING_DOWN' });
      })().then(resolve, reject);
    }));
  });

  test('EW-24 gateway exit leaves no orphan witness process (process exit hook)', async () => {
    const pidFile = path.join(dir, 'orphan.pid');
    const hang = script('hang4.js', `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000);`);
    const gw = script('gateway.js', `const { ExecWitness } = require(${JSON.stringify(path.join(__dirname, '..', 'witness.js'))});
      new ExecWitness({ witnessId: 'w', command: process.execPath, args: [${JSON.stringify(hang)}], timeoutMs: 30000 })
        .cosign({ payload: { checkpointId: 'c', chainLength: 1, headHash: 'h', createdAt: 't' }, payloadHash: 'p' }).catch(() => {});
      const t = setInterval(() => { if (require('fs').existsSync(${JSON.stringify(pidFile)})) { clearInterval(t); process.exit(0); } }, 20);`);
    const r = require('child_process').spawnSync(process.execPath, [gw], { timeout: 20_000, encoding: 'utf8' });
    expect(r.status).toBe(0);
    const pid = +fs.readFileSync(pidFile, 'utf8');
    expect(await waitFor(() => !pidAlive(pid), 3000)).toBe(true); // pre-fix on Linux: the witness outlived the gateway
  });

  test('EW-25 late response after a timeout: the late witness is killed, its output never used, and nothing stays in flight', async () => {
    const pidFile = path.join(dir, 'late.pid');
    // 2026-10-14 (final mission): the witness keeps itself alive after its late reply (setInterval). Before, it exited on
    // its own ~1.5 s in (a late write to the stdout pipe the gateway had already destroyed raised EPIPE), inside the 2 s
    // wait below, so "the late witness is killed" passed even with kill() disabled
    //. It now ignores EPIPE and stays alive: only a kill ends it.
    const late = script('late2.js', `process.stdout.on('error', () => {}); require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setTimeout(() => { ${VALID('w')} }, 1500); setInterval(() => {}, 1000);`);
    const { inFlightWitnessCount } = require('../witness');
    const err = await new ExecWitness({ witnessId: 'w', command: process.execPath, args: [late], timeoutMs: 400, retries: 0 }).cosign(cp(1, H(1))).catch((e) => e);
    expect(err.code).toBe('WITNESS_TIMEOUT');
    expect(inFlightWitnessCount()).toBe(0);
    // 2026-10-14 (launch plan, flake root cause): under parallel unit load the child Node process can take longer than
    // the 400 ms timeout to START, so it is killed before its first statement writes late.pid — the predicate used to
    // readFileSync unconditionally and threw ENOENT. Both outcomes are now checked: if the pid was written, that process
    // must be dead; if it never was, the file must STILL be absent well after a live process would have written it
    // (its first statement), i.e. the witness was killed before it ran at all.
    const written = await waitFor(() => fs.existsSync(pidFile) && fs.readFileSync(pidFile, 'utf8') !== '', 3000);
    if (written) {
      const pid = +fs.readFileSync(pidFile, 'utf8');
      const dead = await waitFor(() => !pidAlive(pid), 2000);
      if (!dead) try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } // never leak it from a failing run
      expect(dead).toBe(true);
    } else expect(fs.existsSync(pidFile)).toBe(false);
  });

  test('EW-26 the reference witness refuses malformed statements (exit 64 → WITNESS_BAD_REQUEST, not retried) and records nothing', async () => {
    const { w } = referenceWitness();
    const logPath = path.join(dir, 'witness-log.jsonl');
    const good = statementFor(cp(3, H(3)), 'w-ext');
    for (const bad of [{ ...good, headHash: undefined }, { ...good, chainLength: 0 }, { ...good, chainLength: 2.5 }, { ...good, checkpointPayloadHash: 'zz' },
      { ...good, checkpointId: '' }, { ...good, checkpointCreatedAt: undefined }, { ...good, previousCheckpointHash: 'not-a-hash' }, { ...good, v: 2 }]) {
      const r = require('child_process').spawnSync(process.execPath, [COSIGN], { input: JSON.stringify({ statement: bad }), env: w.baseEnv, encoding: 'utf8' });
      expect(r.status).toBe(64);
    }
    expect(fs.existsSync(logPath)).toBe(false);
    const exit64 = new ExecWitness({ witnessId: 'w-ext', command: process.execPath, args: [script('e64.js', 'process.exit(64);')], retries: 3, retryDelayMs: 10 });
    await expect(exit64.cosign(cp(3, H(3)))).rejects.toMatchObject({ code: 'WITNESS_BAD_REQUEST' });
  });

  // Concurrent reference-witness processes released together by a go-file barrier (one process per request, exactly how
  // the reference exec witness runs). Resolves [{ status, stdout, stderr }].
  async function concurrentCosign(statements, tag) {
    const { w } = referenceWitness(); const go = path.join(dir, `go-${tag}`);
    const wrap = script(`barrier-${tag}.js`, `const fs=require('fs');const input=fs.readFileSync(0);while(!fs.existsSync(${JSON.stringify(go)})){}
      const real=fs.readFileSync;fs.readFileSync=(p,...a)=>(p===0?input:real(p,...a));require(${JSON.stringify(COSIGN)});`);
    const runs = statements.map((st) => new Promise((resolve) => {
      const c = require('child_process').spawn(process.execPath, [wrap], { env: w.baseEnv }); let stdout = ''; let stderr = '';
      c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
      c.on('close', (status) => resolve({ status, stdout, stderr })); c.stdin.end(JSON.stringify({ statement: st }));
    }));
    await new Promise((r) => setTimeout(r, 1500)); fs.writeFileSync(go, '1');
    return Promise.all(runs);
  }

  test('EW-27 refusal under concurrency: 8 simultaneous requests for ONE position with 8 different heads yield exactly one cosignature; identical concurrent requests all get the same signature', async () => {
    const forks = Array.from({ length: 8 }, (_, i) => statementFor(cp(5, H(500 + i)), 'w-ext'));
    const r = await concurrentCosign(forks, 'forks');
    expect(r.filter((x) => x.status === 0)).toHaveLength(1); // pre-fix: 8 of 8 (probe: 10/10 rounds)
    expect(r.filter((x) => x.status === 3).every((x) => /WITNESS_EQUIVOCATION_REFUSED/.test(x.stderr))).toBe(true);
    expect(r.filter((x) => x.status === 3)).toHaveLength(7);
    const lines = fs.readFileSync(path.join(dir, 'witness-log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(new Set(lines.map((l) => l.statement.headHash)).size).toBe(1);
    // the identical statement replayed concurrently (gateway retry racing a late original) is not an equivocation
    const same = statementFor(cp(6, H(6), lines[0].statement.checkpointPayloadHash), 'w-ext'); // (M8): successors chain to the last witnessed checkpoint
    const r2 = await concurrentCosign(Array(4).fill(same), 'same');
    expect(r2.map((x) => x.status)).toEqual([0, 0, 0, 0]);
    expect(new Set(r2.map((x) => JSON.parse(x.stdout).signature)).size).toBe(1);
  });

  test('EW-28 crash recovery: a torn final log line (crash mid-append) no longer wedges the witness; rules still hold and a corrupt TERMINATED line still fails closed', () => {
    const logPath = path.join(dir, 'tl.jsonl');
    const lw = new LocalFileWitness({ witnessId: 'w-t', keyPath: path.join(dir, 'tk.json'), logPath });
    const c10 = cp(10, H(10)); lw.cosign(c10);
    const torn = fs.readFileSync(logPath, 'utf8').slice(0, 40);
    fs.appendFileSync(logPath, torn); // the process died mid-write of its next record (never acknowledged)
    const c11 = cp(11, H(11), c10.payloadHash); const c12 = cp(12, H(12), c11.payloadHash); // (M8): successors chain to the last witnessed checkpoint
    expect(() => lw.cosign(c11)).not.toThrow(); // pre-fix: SyntaxError on this and every later call
    expect(() => lw.cosign(c12)).not.toThrow();
    expect(() => lw.cosign(cp(9, H(9)))).toThrow(expect.objectContaining({ code: 'WITNESS_ROLLBACK_REFUSED' }));
    expect(() => lw.cosign(cp(12, 'e'.repeat(64)))).toThrow(expect.objectContaining({ code: 'WITNESS_EQUIVOCATION_REFUSED' }));
    const raw = fs.readFileSync(logPath, 'utf8');
    expect(raw).toContain(torn + '\t#torn\n'); // the torn bytes are kept as evidence, closed by the marker, never truncated
    expect(lw._log().map((r) => r.statement.chainLength)).toEqual([10, 11, 12]);
    fs.appendFileSync(logPath, '{"not":"a record"\n'); // corruption that is NOT a torn tail
    expect(() => lw.cosign(cp(13, H(13)))).toThrow(SyntaxError);
  });

  // EW-29 measures the gap between timer ticks while a worker thread scans a large log. That wall-clock measurement is only run where the project can rely on it:
  // Node 23.9 or later (process.threadCpuUsage is available there, and the CI timing job runs Node 24 on a manual run). On older versions the case is skipped and its title says why.
  const [_nodeMajor, _nodeMinor] = process.versions.node.split('.').map(Number);
  const EW29_SUPPORTED = _nodeMajor > 23 || (_nodeMajor === 23 && _nodeMinor >= 9);
  (EW29_SUPPORTED ? test : test.skip)(EW29_SUPPORTED ? 'EW-29 local mode does not block the event loop: the gateway runs LocalFileWitness on a worker thread with a bounded wait; refusal codes survive' : `EW-29 skipped on Node ${process.versions.node}: needs Node 23.9 or later (process.threadCpuUsage); the event-loop gap check does not run`, async () => {
    const { witnessesFromEnv, ThreadedLocalWitness } = require('../witness');
    const keyPath = path.join(dir, 'lk.json'); const logPath = path.join(dir, 'll.jsonl');
    const [w] = witnessesFromEnv({ QODIQA_WITNESS_MODE: 'local', QODIQA_WITNESS_ID: 'w-l', QODIQA_WITNESS_KEY_PATH: keyPath, QODIQA_WITNESS_LOG_PATH: logPath });
    expect(w).toBeInstanceOf(ThreadedLocalWitness);
    const trust = w.publicKeyRecord();
    const first = cp(1, H(1)); const c1 = await w.cosign(first);
    expect(verifyCosignature(statementFor(first, 'w-l'), c1, { keys: [trust] })).toEqual({ ok: true });
    fs.writeFileSync(logPath, fs.readFileSync(logPath, 'utf8').repeat(60_000)); // ~1.7 years of records at the default cadence
    let maxGap = 0; let last = Date.now(); const iv = setInterval(() => { const n = Date.now(); maxGap = Math.max(maxGap, n - last); last = n; }, 5);
    const started = Date.now(); const signed = cp(2, H(2), first.payloadHash); const c2 = await w.cosign(signed); const took = Date.now() - started;
    await new Promise((r) => setTimeout(r, 30)); clearInterval(iv); // let a timer delayed by a synchronous block fire and be measured
    expect(verifyCosignature(statementFor(signed, 'w-l'), c2, { keys: [trust] })).toEqual({ ok: true });
    // control: the same scan done synchronously in-process (the pre-fix local mode) blocks for `blocked` ms
    const c3 = cp(3, H(3), signed.payloadHash); // (M8): successors chain to the last witnessed checkpoint
    const t0 = process.hrtime.bigint(); new LocalFileWitness({ witnessId: 'w-l', keyPath, logPath }).cosign(c3); const blocked = Number(process.hrtime.bigint() - t0) / 1e6;
    expect(blocked).toBeGreaterThan(50);
    expect(took).toBeGreaterThan(0);
    expect(maxGap).toBeLessThan(blocked); // pre-fix: the timer stalls for the whole scan (maxGap >= blocked)
    expect(maxGap).toBeLessThan(50);
    await expect(w.cosign(cp(1, H(999)))).rejects.toMatchObject({ code: 'WITNESS_ROLLBACK_REFUSED' });
    await expect(w.cosign(cp(3, H(998)))).rejects.toMatchObject({ code: 'WITNESS_EQUIVOCATION_REFUSED' });
    const slow = new ThreadedLocalWitness({ witnessId: 'w-l', keyPath, logPath, timeoutMs: 1 });
    await expect(slow.cosign(cp(4, H(4), c3.payloadHash))).rejects.toMatchObject({ code: 'WITNESS_TIMEOUT' });
  });

  test('EW-30 audit + checkpoint binding end to end: an anchor verifies only for the exact signed checkpoint payload its cosignature covers', async () => {
    const { signCheckpoint } = require('../../checkpoint/checkpoint');
    const { verifyChainAgainstAnchors } = require('../anchors');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const ck = { keyId: 'ckpt-test', version: 1, privDer: privateKey.export({ type: 'pkcs8', format: 'der' }), pubDer: publicKey.export({ type: 'spki', format: 'der' }) };
    const ks = { keyStore: { ensureActiveKey: () => ck } };
    const a = signCheckpoint({ chainLength: 8, headHash: H(8) }, ks);
    const b = signCheckpoint({ chainLength: 8, headHash: H(8) }, ks); // same position and head, different checkpoint (id/createdAt)
    const { w, trust } = referenceWitness();
    const anchor = { anchorVersion: 1, checkpoint: a, cosignatures: [await w.cosign(a)] };
    const args = (an) => ({ anchors: [an], chainLength: 8, headHashAt: async () => H(8), checkpoints: [a], resolveCheckpointKey: () => ck.pubDer, trustedWitnessKeys: { keys: [trust] } });
    expect(await verifyChainAgainstAnchors(args(anchor))).toEqual({ ok: true, checked: 1, findings: [] });
    // the cosignature for A presented with checkpoint B (a genuine, validly signed checkpoint for the same position)
    const swapped = await verifyChainAgainstAnchors(args({ ...anchor, checkpoint: b }));
    expect(swapped.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['ANCHOR_NOT_WITNESSED', 'CHECKPOINT_DELETED'])); // B is not in the live set: A is
    // A's payload altered with its payloadHash recomputed by the attacker: the checkpoint signature and the cosignature both fail
    const altered = { ...a, payload: { ...a.payload, pgSeq: 999 } };
    altered.payloadHash = require('../../checkpoint/checkpoint').checkpointDigest(altered.payload).toString('hex');
    const r = await verifyChainAgainstAnchors(args({ ...anchor, checkpoint: altered }));
    expect(r.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['ANCHOR_CHECKPOINT_INVALID', 'ANCHOR_NOT_WITNESSED']));
  });
});
